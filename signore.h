#pragma once
//
// signore.h
// Sends PE files collected in Pending_Sign\ to the remote signing server,
// downloads the signed ZIP back, and replaces the files in Pending_Sign\.
// Run after snatcher (option 1) and before courier (option 2).
//
// Credentials are stored encrypted in signore.env (DPAPI, current user scope).
// Use option 5 (RunSetupSigningCreds) to create or update signore.env.
//

#include "courier.h"    // ParseManifest, ManifestEntry, s2w, w2u
                        // also pulls in wincrypt.h  ->  CryptProtectData / CryptUnprotectData
                        // and Crypt32.lib via auditor.h

#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")

#include <map>
#include <random>
#include <chrono>
#include <sstream>

// ---------------------------------------------------------------------------
// DPAPI credential store  (signore.env – binary blob next to the exe)
// ---------------------------------------------------------------------------

// Returns the path to signore.env (same directory as the running exe).
static fs::path Signore_EnvPath()
{
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return fs::path(buf).parent_path() / L"signore.env";
}

// Encrypt `plaintext` with DPAPI (current-user scope) and write to `destPath`.
// Returns true on success.
static bool Signore_SaveEnvEncrypted(
    const fs::path& destPath,
    const std::string& plaintext)
{
    DATA_BLOB in  = {};
    DATA_BLOB out = {};
    in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()));
    in.cbData = static_cast<DWORD>(plaintext.size());

    if (!CryptProtectData(&in, L"signore.env", nullptr, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &out))
        return false;

    std::ofstream f(destPath, std::ios::binary);
    bool ok = false;
    if (f)
    {
        f.write(reinterpret_cast<const char*>(out.pbData), out.cbData);
        ok = f.good();
    }
    LocalFree(out.pbData);
    return ok;
}

// Read `srcPath`, decrypt with DPAPI, parse key=value lines.
// Returns empty map if the file is missing or decryption fails.
static std::map<std::string, std::string> Signore_LoadEnvEncrypted(
    const fs::path& srcPath)
{
    std::map<std::string, std::string> vars;

    // Read raw blob
    std::ifstream f(srcPath, std::ios::binary);
    if (!f) return vars;
    std::vector<BYTE> blob(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    f.close();
    if (blob.empty()) return vars;

    // Decrypt
    DATA_BLOB in  = {};
    DATA_BLOB out = {};
    in.pbData = blob.data();
    in.cbData = static_cast<DWORD>(blob.size());

    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &out))
        return vars;

    std::string plain(reinterpret_cast<char*>(out.pbData), out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);

    // Parse key=value lines (same format as a plain .env)
    std::istringstream ss(plain);
    std::string line;
    while (std::getline(ss, line))
    {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == '\n' ||
                isspace((unsigned char)line.back())))
            line.pop_back();

        if (line.empty() || line[0] == '#') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        while (!key.empty() && isspace((unsigned char)key.back())) key.pop_back();
        size_t s = 0;
        while (s < val.size() && isspace((unsigned char)val[s])) ++s;
        val = val.substr(s);

        vars[key] = val;
    }

    // Wipe the plain-text copy from heap memory before returning
    SecureZeroMemory(plain.data(), plain.size());
    return vars;
}

// ---------------------------------------------------------------------------
// Masked password input
// ---------------------------------------------------------------------------

static std::string Signore_ReadPassword()
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD  mode = 0;
    GetConsoleMode(hIn, &mode);
    // Disable echo and line-input so we own every keypress
    SetConsoleMode(hIn, mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));

    std::wstring wpass;   // track as wide chars so backspace removes one glyph
    INPUT_RECORD rec  = {};
    DWORD        nRead = 0;

    while (true)
    {
        if (!ReadConsoleInputW(hIn, &rec, 1, &nRead)) break;
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown) continue;

        WORD    vk = rec.Event.KeyEvent.wVirtualKeyCode;
        wchar_t ch = rec.Event.KeyEvent.uChar.UnicodeChar;

        if (vk == VK_RETURN) break;

        if (vk == VK_BACK)
        {
            if (!wpass.empty())
            {
                wpass.pop_back();
                std::cout << "\b \b" << std::flush;   // erase the last *
            }
            continue;
        }

        if (ch >= L' ')   // printable character
        {
            wpass += ch;
            std::cout << '*' << std::flush;
        }
    }

    SetConsoleMode(hIn, mode);
    std::cout << "\n";

    // Convert wide password to UTF-8 for the rest of the code
    return w2u(wpass);
}

// ---------------------------------------------------------------------------
// URL parser  (supports http:// and https://, optional base path)
// ---------------------------------------------------------------------------

struct SigUrl
{
    bool          secure   = false;
    std::wstring  host;
    INTERNET_PORT port     = 0;
    std::wstring  basePath;   // e.g. L"" or L"/signer"
};

static bool Signore_ParseUrl(const std::string& raw, SigUrl& out)
{
    std::string u = raw;
    if (u.size() >= 8 && u.substr(0, 8) == "https://") { out.secure = true;  u = u.substr(8); }
    else if (u.size() >= 7 && u.substr(0, 7) == "http://") { out.secure = false; u = u.substr(7); }
    else return false;

    size_t slash = u.find('/');
    std::string hostPort = (slash != std::string::npos) ? u.substr(0, slash) : u;
    std::string path     = (slash != std::string::npos) ? u.substr(slash)    : std::string{};
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    out.basePath = s2w(path);

    auto colon = hostPort.rfind(':');
    if (colon != std::string::npos)
    {
        out.host = s2w(hostPort.substr(0, colon));
        try   { out.port = static_cast<INTERNET_PORT>(std::stoi(hostPort.substr(colon + 1))); }
        catch (...) { return false; }
    }
    else
    {
        out.host = s2w(hostPort);
        out.port = out.secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Error formatting helper
// ---------------------------------------------------------------------------

static std::string Signore_FormatError(DWORD code)
{
    char buf[512] = {};
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        GetModuleHandleA("winhttp.dll"),
        code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, sizeof(buf) - 1, nullptr);
    if (n == 0)   // retry from system only
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buf, sizeof(buf) - 1, nullptr);

    // Strip trailing whitespace / newlines
    std::string msg(buf);
    while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' ||
                             isspace((unsigned char)msg.back())))
        msg.pop_back();

    char hex[32];
    snprintf(hex, sizeof(hex), " (0x%08X)", code);
    return msg.empty() ? std::string("Unknown error") + hex : msg + hex;
}

// ---------------------------------------------------------------------------
// Single HTTP request (no auto-redirect, ignores SSL cert errors like curl -k)
// ---------------------------------------------------------------------------

struct SigResponse
{
    DWORD             status = 0;
    std::string       setCookie;    // raw Set-Cookie value (null-separated for multi-values)
    std::string       location;     // Location header (for 3xx redirects)
    std::vector<BYTE> body;
};

// errMsg receives a human-readable description of the failure step + error code.
// receiveTimeoutMs: overrides the WinHTTP receive-response timeout (0 = keep default 30 s).
static bool Signore_Send(
    HINTERNET           hSession,
    const SigUrl&       url,
    const std::wstring& method,
    const std::wstring& path,
    const std::wstring& extraHeaders,
    const void*         bodyPtr,
    DWORD               bodyLen,
    SigResponse&        resp,
    std::string*        errMsg          = nullptr,
    DWORD               receiveTimeoutMs = 0)
{
    auto fail = [&](const char* step) -> bool
    {
        DWORD err = GetLastError();
        if (errMsg)
            *errMsg = std::string(step) + ": " + Signore_FormatError(err);
        WinHttpCloseHandle(hSession);   // caller should not reuse on error
        return false;
    };

    HINTERNET hConn = WinHttpConnect(hSession, url.host.c_str(), url.port, 0);
    if (!hConn) return fail("WinHttpConnect");

    DWORD reqFlags = url.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(
        hConn, method.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, reqFlags);
    if (!hReq) { WinHttpCloseHandle(hConn); return fail("WinHttpOpenRequest"); }

    auto failReq = [&](const char* step) -> bool
    {
        DWORD err = GetLastError();
        if (errMsg)
            *errMsg = std::string(step) + ": " + Signore_FormatError(err);
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        return false;
    };

    // Mirror curl -k: ignore SSL certificate errors
    if (url.secure)
    {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                       | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    // Do NOT follow redirects so we can capture the Set-Cookie on the login 302
    DWORD noRedir = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY, &noRedir, sizeof(noRedir));

    // WinHttpSetTimeouts is the reliable way to override timeouts on a request handle.
    // sendTimeout=0 means no per-chunk send cap (important for large upload bodies).
    // receiveTimeout controls how long WinHttpReceiveResponse waits for the server.
    WinHttpSetTimeouts(hReq,
        0,                                              // resolve  (0 = no timeout)
        60 * 1000,                                      // connect  (60 s)
        0,                                              // send     (no timeout)
        receiveTimeoutMs > 0 ? receiveTimeoutMs : 30 * 1000);   // receive (caller or 30 s)

    if (!extraHeaders.empty())
        WinHttpAddRequestHeaders(hReq, extraHeaders.c_str(),
            (DWORD)extraHeaders.size(), WINHTTP_ADDREQ_FLAG_ADD);

    // Declare total length upfront but send no inline body — stream via WinHttpWriteData
    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, bodyLen, 0))
        return failReq("WinHttpSendRequest");

    if (bodyLen > 0 && bodyPtr != nullptr)
    {
        const BYTE* p       = static_cast<const BYTE*>(bodyPtr);
        DWORD       sent    = 0;
        DWORD       remaining = bodyLen;
        while (remaining > 0)
        {
            DWORD toWrite = min(remaining, static_cast<DWORD>(64 * 1024));
            DWORD written = 0;
            if (!WinHttpWriteData(hReq, p, toWrite, &written))
            {
                DWORD err = GetLastError();
                if (errMsg)
                {
                    char detail[128];
                    snprintf(detail, sizeof(detail),
                        "WinHttpWriteData at %.1f / %.1f KB: ",
                        sent / 1024.0, bodyLen / 1024.0);
                    *errMsg = std::string(detail) + Signore_FormatError(err);
                }
                WinHttpCloseHandle(hReq);
                WinHttpCloseHandle(hConn);
                return false;
            }
            p         += written;
            sent      += written;
            remaining -= written;
        }
    }

    if (!WinHttpReceiveResponse(hReq, nullptr))
        return failReq("WinHttpReceiveResponse");

    // Status code
    DWORD sc = 0, scSz = sizeof(sc);
    WinHttpQueryHeaders(hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &sc, &scSz, WINHTTP_NO_HEADER_INDEX);
    resp.status = sc;

    // Set-Cookie header (may be absent)
    DWORD ckSz = 0;
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_SET_COOKIE,
        WINHTTP_HEADER_NAME_BY_INDEX,
        WINHTTP_NO_OUTPUT_BUFFER, &ckSz, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && ckSz > 0)
    {
        std::wstring buf(ckSz / sizeof(wchar_t) + 1, L'\0');
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_SET_COOKIE,
            WINHTTP_HEADER_NAME_BY_INDEX,
            buf.data(), &ckSz, WINHTTP_NO_HEADER_INDEX);
        resp.setCookie = w2u(buf);
    }

    // Location header (present on 3xx redirects)
    DWORD locSz = 0;
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION,
        WINHTTP_HEADER_NAME_BY_INDEX,
        WINHTTP_NO_OUTPUT_BUFFER, &locSz, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && locSz > 0)
    {
        std::wstring buf(locSz / sizeof(wchar_t) + 1, L'\0');
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION,
            WINHTTP_HEADER_NAME_BY_INDEX,
            buf.data(), &locSz, WINHTTP_NO_HEADER_INDEX);
        resp.location = w2u(buf);
    }

    // Body
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0)
    {
        size_t off = resp.body.size();
        resp.body.resize(off + avail);
        DWORD got = 0;
        WinHttpReadData(hReq, resp.body.data() + off, avail, &got);
        if (got < avail) resp.body.resize(off + got);
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    return true;
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

// Extract "name=value" pairs from a raw Set-Cookie string.
// WinHTTP may return multiple Set-Cookie headers separated by null chars.
static std::string Signore_ParseCookie(const std::string& raw)
{
    std::string result;
    std::string src = raw;
    for (char& c : src) if (c == '\0') c = '\n';

    std::istringstream ss(src);
    std::string line;
    while (std::getline(ss, line))
    {
        while (!line.empty() && (line.back() == '\r' || isspace((unsigned char)line.back())))
            line.pop_back();
        if (line.empty()) continue;

        auto semi = line.find(';');
        std::string nv = (semi != std::string::npos) ? line.substr(0, semi) : line;
        while (!nv.empty() && isspace((unsigned char)nv.front())) nv.erase(nv.begin());
        while (!nv.empty() && isspace((unsigned char)nv.back())) nv.pop_back();

        if (!nv.empty())
        {
            if (!result.empty()) result += "; ";
            result += nv;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Multipart form-data builder
// ---------------------------------------------------------------------------

static std::string Signore_MakeBoundary()
{
    static const char hex[] = "0123456789abcdef";
    std::string b = "----SignoreBoundary";
    auto seed = static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    std::mt19937 rng(seed);
    std::uniform_int_distribution<int> d(0, 15);
    for (int i = 0; i < 16; ++i) b += hex[d(rng)];
    return b;
}

// Each entry: {fieldName, absoluteFilePath}
static std::vector<BYTE> Signore_BuildMultipart(
    const std::string& boundary,
    const std::vector<std::pair<std::string, fs::path>>& files)
{
    std::vector<BYTE> body;
    auto add = [&](const std::string& s)
        { body.insert(body.end(), s.begin(), s.end()); };

    for (const auto& [field, path] : files)
    {
        std::string fname = w2u(path.filename().wstring());
        add("--" + boundary + "\r\n");
        add("Content-Disposition: form-data; name=\"" + field +
            "\"; filename=\"" + fname + "\"\r\n");
        add("Content-Type: application/octet-stream\r\n\r\n");

        std::ifstream f(path, std::ios::binary);
        if (f)
        {
            std::vector<char> buf(
                (std::istreambuf_iterator<char>(f)),
                std::istreambuf_iterator<char>());
            body.insert(body.end(), buf.begin(), buf.end());
        }
        add("\r\n");
    }
    add("--" + boundary + "--\r\n");
    return body;
}

// ---------------------------------------------------------------------------
// ZIP extraction via PowerShell Expand-Archive
// ---------------------------------------------------------------------------

static bool Signore_ExtractZip(const fs::path& zipPath, const fs::path& destDir)
{
    std::wstring cmd =
        L"powershell.exe -NoProfile -NonInteractive -Command "
        L"\"Expand-Archive -LiteralPath '" + zipPath.wstring() +
        L"' -DestinationPath '" + destDir.wstring() +
        L"' -Force\"";

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(nullptr, cmd.data(),
            nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &si, &pi))
        return false;

    WaitForSingleObject(pi.hProcess, 60'000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
}

// ---------------------------------------------------------------------------
// Option 5 – Setup Signing Credentials
// ---------------------------------------------------------------------------

inline void RunSetupSigningCreds()
{
    fs::path envPath = Signore_EnvPath();

    if (fs::exists(envPath))
        std::cout << "  [INFO] Existing signore.env will be overwritten.\n\n";

    std::string baseUrl, username, password;

    std::cout << "BASE_URL  (e.g. https://host:port): ";
    std::getline(std::cin, baseUrl);
    while (!baseUrl.empty() && isspace((unsigned char)baseUrl.back())) baseUrl.pop_back();

    // Quick sanity check on the URL before storing
    {
        SigUrl tmp;
        if (!Signore_ParseUrl(baseUrl, tmp))
        {
            std::cerr << "Error: URL must start with http:// or https://\n";
            return;
        }
    }

    std::cout << "USERNAME: ";
    std::getline(std::cin, username);
    while (!username.empty() && isspace((unsigned char)username.back())) username.pop_back();

    std::cout << "PASSWORD: ";
    password = Signore_ReadPassword();   // echo disabled

    if (baseUrl.empty() || username.empty() || password.empty())
    {
        std::cerr << "Error: All fields are required.\n";
        SecureZeroMemory(password.data(), password.size());
        return;
    }

    // Build plain-text .env content
    std::string plain =
        "BASE_URL=" + baseUrl  + "\n"
        "USERNAME=" + username + "\n"
        "PASSWORD=" + password + "\n";

    SecureZeroMemory(password.data(), password.size());

    if (!Signore_SaveEnvEncrypted(envPath, plain))
    {
        std::cerr << "Error: DPAPI encryption failed (error " << GetLastError() << ").\n";
        SecureZeroMemory(plain.data(), plain.size());
        return;
    }

    SecureZeroMemory(plain.data(), plain.size());

    std::cout << "Credentials saved to: " << w2u(envPath.wstring()) << "\n"
              << "  (DPAPI-encrypted, readable only by this Windows user on this machine)\n";
}

// ---------------------------------------------------------------------------
// Option 4 – Sign Collected Files
// ---------------------------------------------------------------------------

inline void RunSignCollected()
{
    // 1. Pending_Sign path
    std::string pendingStr;
    std::cout << "Enter path to Pending_Sign folder: ";
    std::getline(std::cin, pendingStr);

    fs::path pendingDir = s2w(pendingStr);
    if (!fs::is_directory(pendingDir))
    {
        std::cerr << "Error: Not a valid directory: " << pendingStr << "\n";
        return;
    }
    if (!fs::exists(pendingDir / "manifest.json"))
    {
        std::cerr << "Error: manifest.json not found in " << pendingStr << "\n";
        return;
    }

    // 2. Load and decrypt signore.env
    fs::path envPath = Signore_EnvPath();
    if (!fs::exists(envPath))
    {
        std::cerr << "Error: signore.env not found at " << w2u(envPath.wstring()) << "\n"
                  << "  Run option 5 to set up signing credentials.\n";
        return;
    }

    auto vars = Signore_LoadEnvEncrypted(envPath);
    for (const char* key : { "BASE_URL", "USERNAME", "PASSWORD" })
    {
        if (vars.find(key) == vars.end() || vars[key].empty())
        {
            std::cerr << "Error: Missing '" << key << "' in signore.env.\n"
                      << "  Re-run option 5 to recreate credentials.\n";
            return;
        }
    }

    SigUrl url;
    if (!Signore_ParseUrl(vars["BASE_URL"], url))
    {
        std::cerr << "Error: Invalid BASE_URL in signore.env.\n";
        return;
    }
    const std::string& username = vars["USERNAME"];
    const std::string& password = vars["PASSWORD"];

    // 3. Read manifest
    std::vector<ManifestEntry> entries;
    try { entries = ParseManifest(pendingDir / "manifest.json"); }
    catch (const std::exception& ex)
    {
        std::cerr << "Error reading manifest: " << ex.what() << "\n";
        return;
    }
    if (entries.empty()) { std::cout << "Manifest is empty – nothing to sign.\n"; return; }

    // Collect the staged PE files from Pending_Sign
    struct UploadItem { fs::path src; std::string relPath; };
    std::vector<UploadItem> uploadItems;
    for (const auto& e : entries)
    {
        fs::path src = pendingDir / s2w(e.relativePath);

        if (!IsPEExtension(src))
        {
            std::cerr << "  [SKIP] Not a PE file, will not upload: " << e.relativePath << "\n";
            continue;
        }
        if (fs::exists(src))
            uploadItems.push_back({ src, e.relativePath });
        else
            std::cerr << "  [WARN] Missing staged file: " << e.relativePath << "\n";
    }
    if (uploadItems.empty()) { std::cerr << "Error: No staged files found.\n"; return; }

    // Flatten to the format BuildMultipart expects
    std::vector<std::pair<std::string, fs::path>> uploadFiles;
    uploadFiles.reserve(uploadItems.size());
    for (const auto& item : uploadItems)
        uploadFiles.emplace_back("files", item.src);

    // 4. Open WinHTTP session
    HINTERNET hSession = WinHttpOpen(
        L"unsigned_runner/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
    {
        std::cerr << "Error: WinHttpOpen failed: "
                  << Signore_FormatError(GetLastError()) << "\n";
        return;
    }

    std::string httpErr;

    // 5. Login
    std::cout << "Logging in to " << vars["BASE_URL"] << "/login ...\n";
    std::string loginBody = "username=" + username + "&password=" + password;
    std::wstring loginPath = url.basePath + L"/login";

    SigResponse loginResp;
    if (!Signore_Send(hSession, url, L"POST", loginPath,
            L"Content-Type: application/x-www-form-urlencoded\r\n",
            loginBody.data(), (DWORD)loginBody.size(), loginResp, &httpErr))
    {
        std::cerr << "Error: Login failed – " << httpErr << "\n";
        return;
    }

    // Server sends the login page again when credentials are wrong (mirrors PS1 check)
    std::string loginBodyStr(loginResp.body.begin(), loginResp.body.end());
    if (loginBodyStr.find("Login - File Signer") != std::string::npos)
    {
        std::cerr << "Error: Login failed – incorrect username or password.\n";
        return;
    }

    std::string cookie = Signore_ParseCookie(loginResp.setCookie);
    if (cookie.empty())
    {
        std::cerr << "Error: No session cookie received from server.\n";
        return;
    }
    std::cout << "Login successful.\n";

    // Build filename -> entries map once (shared across all batches)
    std::map<std::string, std::vector<const ManifestEntry*>> byName;
    for (const auto& e : entries)
        byName[w2u(fs::path(s2w(e.relativePath)).filename().wstring())].push_back(&e);

    wchar_t tempPathBuf[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempPathBuf);
    fs::path tempZip     = fs::path(tempPathBuf) / L"signore_signed.zip";
    fs::path tempExtract = fs::path(tempPathBuf) / L"signore_extract";

    constexpr size_t kBatchSize       = 5;
    constexpr DWORD  kUploadTimeoutMs = 10 * 60 * 1000;   // 10 min for server-side signing

    size_t replaced = 0, skipped = 0;
    size_t batchCount = (uploadFiles.size() + kBatchSize - 1) / kBatchSize;

    // 6. Upload → download → extract in batches
    for (size_t b = 0; b < uploadFiles.size(); b += kBatchSize)
    {
        size_t bEnd     = min(b + kBatchSize, uploadFiles.size());
        size_t bNum     = b / kBatchSize + 1;

        std::cout << "\nBatch " << bNum << "/" << batchCount
                  << " (" << (bEnd - b) << " file(s)):\n";

        // List files in this batch
        for (size_t i = b; i < bEnd; ++i)
        {
            std::error_code ec;
            auto sz = fs::file_size(uploadItems[i].src, ec);
            char idx[16];
            snprintf(idx, sizeof(idx), "[%2zu/%2zu]", i + 1, uploadFiles.size());
            std::cout << "  " << idx << "  " << uploadItems[i].relPath;
            if (!ec) std::cout << "  (" << sz / 1024 << " KB)";
            std::cout << "\n";
        }

        // Build multipart body for this batch only
        std::vector<std::pair<std::string, fs::path>> batchFiles(
            uploadFiles.begin() + b, uploadFiles.begin() + bEnd);

        std::string      boundary     = Signore_MakeBoundary();
        std::vector<BYTE> multipartBody = Signore_BuildMultipart(boundary, batchFiles);

        std::cout << "Uploading (" << multipartBody.size() / 1024 << " KB)...\n";

        std::wstring uploadHeaders =
            L"Cookie: " + s2w(cookie) + L"\r\n"
            L"Content-Type: multipart/form-data; boundary=" + s2w(boundary) + L"\r\n";

        SigResponse uploadResp;
        if (!Signore_Send(hSession, url, L"POST", url.basePath + L"/upload",
                uploadHeaders, multipartBody.data(), (DWORD)multipartBody.size(),
                uploadResp, &httpErr, kUploadTimeoutMs))
        {
            std::cerr << "Error: Upload failed – " << httpErr << "\n";
            WinHttpCloseHandle(hSession);
            return;
        }
        {
            std::string body(uploadResp.body.begin(), uploadResp.body.end());
            if (body.find("Login - File Signer") != std::string::npos)
            {
                std::cerr << "Error: Upload rejected – session invalid.\n";
                WinHttpCloseHandle(hSession);
                return;
            }
        }
        // Mirror curl -c: capture any updated session cookie from upload response
        if (!uploadResp.setCookie.empty())
        {
            std::string updated = Signore_ParseCookie(uploadResp.setCookie);
            if (!updated.empty()) cookie = updated;
        }
        std::cout << "Upload completed.\n";

        // Download signed ZIP
        std::cout << "Downloading signed files...\n";
        std::wstring dlHeaders = L"Cookie: " + s2w(cookie) + L"\r\n";

        SigResponse dlResp;
        if (!Signore_Send(hSession, url, L"GET", url.basePath + L"/download-all",
                dlHeaders, nullptr, 0, dlResp, &httpErr))
        {
            std::cerr << "Error: Download failed – " << httpErr << "\n";
            WinHttpCloseHandle(hSession);
            return;
        }

        // Follow redirect (mirrors curl -L)
        if (dlResp.status / 100 == 3 && !dlResp.location.empty())
        {
            std::cout << "  [redirect] " << dlResp.location << "\n";
            SigUrl      redirUrl  = url;
            std::wstring redirPath;
            if (dlResp.location.substr(0, 4) == "http")
            {
                Signore_ParseUrl(dlResp.location, redirUrl);
                redirPath = redirUrl.basePath;
            }
            else
            {
                redirPath = s2w(dlResp.location);
            }
            dlResp = {};
            if (!Signore_Send(hSession, redirUrl, L"GET", redirPath,
                    dlHeaders, nullptr, 0, dlResp, &httpErr))
            {
                std::cerr << "Error: Download (redirect) failed – " << httpErr << "\n";
                WinHttpCloseHandle(hSession);
                return;
            }
        }

        if (dlResp.body.size() < 200)
        {
            std::cerr << "Error: Downloaded content too small ("
                      << dlResp.body.size() << " bytes) – server response:\n";
            std::cerr.write(reinterpret_cast<const char*>(dlResp.body.data()),
                dlResp.body.size());
            std::cerr << "\n";
            WinHttpCloseHandle(hSession);
            return;
        }

        if (dlResp.body[0] != 'P' || dlResp.body[1] != 'K' ||
            dlResp.body[2] != 0x03 || dlResp.body[3] != 0x04)
        {
            std::cerr << "Error: Response is not a ZIP file. Server said:\n";
            std::cerr.write(reinterpret_cast<const char*>(dlResp.body.data()),
                min(dlResp.body.size(), static_cast<size_t>(512)));
            std::cerr << "\n";
            WinHttpCloseHandle(hSession);
            return;
        }

        std::cout << "Downloaded: " << dlResp.body.size() << " bytes.\n";

        // Save ZIP
        {
            std::ofstream zf(tempZip, std::ios::binary);
            if (!zf) { std::cerr << "Error: Cannot write temp ZIP.\n";
                       WinHttpCloseHandle(hSession); return; }
            zf.write(reinterpret_cast<const char*>(dlResp.body.data()),
                     static_cast<std::streamsize>(dlResp.body.size()));
        }
        std::cout << "Saved to: " << w2u(tempZip.wstring()) << "\n";

        // Extract
        std::error_code ec;
        fs::remove_all(tempExtract, ec);
        fs::create_directories(tempExtract, ec);

        if (!Signore_ExtractZip(tempZip, tempExtract))
        {
            std::cerr << "Error: ZIP extraction failed.\n";
            WinHttpCloseHandle(hSession);
            return;
        }

        // Log extracted files
        std::cout << "Extracted files:\n";
        size_t extractCount = 0;
        for (auto& item : fs::recursive_directory_iterator(tempExtract, ec))
        {
            if (!item.is_regular_file(ec)) continue;
            auto sz = fs::file_size(item.path(), ec);
            std::cout << "  " << w2u(item.path().lexically_relative(tempExtract).wstring())
                      << "  (" << sz / 1024 << " KB)\n";
            ++extractCount;
        }
        if (extractCount == 0)
            std::cerr << "  (none – ZIP may be empty or extraction silently failed)\n";

        // Replace files in Pending_Sign for this batch
        std::cout << "Replacing files in Pending_Sign...\n";

        for (auto& item : fs::recursive_directory_iterator(tempExtract, ec))
        {
            if (!item.is_regular_file(ec)) continue;

            std::string extractedName = w2u(item.path().filename().wstring());

            auto tryReplace = [&](const std::string& name) -> bool
            {
                auto it = byName.find(name);
                if (it == byName.end()) return false;

                for (const ManifestEntry* me : it->second)
                {
                    fs::path dest = pendingDir / s2w(me->relativePath);
                    fs::copy_file(item.path(), dest,
                        fs::copy_options::overwrite_existing, ec);
                    if (ec)
                    {
                        std::cerr << "  [ERROR] " << me->relativePath
                                  << ": " << ec.message() << "\n";
                        return false;
                    }
                    std::cout << "  [OK] " << me->relativePath;
                    try { std::cout << (IsFileSigned(dest) > 0
                            ? " (verified signed)\n" : " (STILL UNSIGNED)\n"); }
                    catch (...) { std::cout << "\n"; }
                    ++replaced;
                }
                return true;
            };

            if (!tryReplace(extractedName))
            {
                std::string alt = extractedName;
                bool changed = false;
                for (char& c : alt) if (c == ' ')  { c = '_'; changed = true; }
                if (!changed)
                    for (char& c : alt) if (c == '_') { c = ' '; changed = true; }

                if (!changed || !tryReplace(alt))
                {
                    std::cout << "  [SKIP] No manifest match for: " << extractedName << "\n";
                    ++skipped;
                }
            }
        }

        fs::remove_all(tempExtract, ec);   // clean up before next batch
    }   // end batch loop

    WinHttpCloseHandle(hSession);

    std::cout << "\n--- Summary ---\n"
              << "  Replaced : " << replaced << "\n"
              << "  Skipped  : " << skipped  << "\n";
}
