#pragma once
//
// snatcher.h
// Scans a directory for unsigned PE files and collects them into Pending_Sign\.
//

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include "auditor.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Shared helpers (used by both snatcher and courier)
// ---------------------------------------------------------------------------

inline std::wstring s2w(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

inline std::string w2u(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Minimal JSON string escaping
inline std::string jsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 4);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20)
            {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else out += c;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Manifest entry (shared with courier)
// ---------------------------------------------------------------------------

struct ManifestEntry
{
    std::string relativePath;   // relative path inside Pending_Sign  e.g. "001/test.exe"
    std::string originalPath;   // original full path
};

// ---------------------------------------------------------------------------
// Signature check via WinVerifyTrust
// Returns true  -> file is signed (and signature is valid)
// Returns false -> unsigned or verification failed
// (Superseded by auditor::IsFileSigned — kept for reference)
// ---------------------------------------------------------------------------

//inline bool IsFileSigned(const fs::path& filePath)
//{
//    std::wstring wpath = filePath.wstring();
//
//    WINTRUST_FILE_INFO fileInfo = {};
//    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
//    fileInfo.pcwszFilePath = wpath.c_str();
//    fileInfo.hFile = nullptr;
//    fileInfo.pgKnownSubject = nullptr;
//
//    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
//
//    WINTRUST_DATA trustData = {};
//    trustData.cbStruct = sizeof(WINTRUST_DATA);
//    trustData.pPolicyCallbackData = nullptr;
//    trustData.pSIPClientData = nullptr;
//    trustData.dwUIChoice = WTD_UI_NONE;
//    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;   // skip online revocation for speed
//    trustData.dwUnionChoice = WTD_CHOICE_FILE;
//    trustData.pFile = &fileInfo;
//    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
//    trustData.hWVTStateData = nullptr;
//    trustData.pwszURLReference = nullptr;
//    trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
//    trustData.dwUIContext = 0;
//
//    LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE),
//        &policyGuid, &trustData);
//
//    // Close the state data
//    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
//    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGuid, &trustData);
//
//    return (status == ERROR_SUCCESS);
//}

// ---------------------------------------------------------------------------
// Pending_Sign folder layout helpers
// ---------------------------------------------------------------------------

inline const std::set<std::string> kPEExtensions = { ".exe", ".dll", ".sys" };

inline bool IsPEExtension(const fs::path& p)
{
    std::string ext = p.extension().string();
    for (auto& c : ext) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return kPEExtensions.count(ext) > 0;
}

// Returns the destination path inside pendingDir for a given filename,
// creating a numbered sub-folder if the name is already taken.
// Also returns the relative path string (e.g. "001/foo.dll" or just "foo.dll").
inline std::pair<fs::path, std::string>
ResolveDestination(const fs::path& pendingDir, const std::string& filename)
{
    fs::path direct = pendingDir / filename;
    if (!fs::exists(direct))
        return { direct, filename };

    for (int i = 1; i <= 99999; ++i)
    {
        std::ostringstream ss;
        ss << std::setw(3) << std::setfill('0') << i;
        std::string folderName = ss.str();
        fs::path sub = pendingDir / folderName;
        fs::path candidate = sub / filename;
        if (!fs::exists(candidate))
        {
            std::error_code ec;
            fs::create_directories(sub, ec);
            return { candidate, folderName + "/" + filename };
        }
    }
    throw std::runtime_error("Could not find a free numbered subfolder in Pending_Sign");
}

inline void WriteManifest(const fs::path& manifestPath,
    const std::vector<ManifestEntry>& entries)
{
    std::ofstream f(manifestPath);
    if (!f) throw std::runtime_error("Cannot write manifest: " + manifestPath.string());

    f << "[\n";
    for (size_t i = 0; i < entries.size(); ++i)
    {
        f << "  {\n"
            << "    \"relative_path\": \"" << jsonEscape(entries[i].relativePath) << "\",\n"
            << "    \"original_path\": \"" << jsonEscape(entries[i].originalPath) << "\"\n"
            << "  }";
        if (i + 1 < entries.size()) f << ",";
        f << "\n";
    }
    f << "]\n";
}

// ---------------------------------------------------------------------------
// Option 1 – Scan & Collect
// ---------------------------------------------------------------------------

inline void RunScanAndCollect()
{
    std::string targetStr;
    std::wcout << L"Enter target directory path: ";
    std::getline(std::cin, targetStr);

    fs::path targetDir = s2w(targetStr);
    if (!fs::is_directory(targetDir))
    {
        std::cerr << "Error: Not a valid directory: " << targetStr << "\n";
        return;
    }

    fs::path pendingDir = targetDir / "Pending_Sign";
    std::error_code ec;
    fs::create_directories(pendingDir, ec);
    if (ec)
    {
        std::cerr << "Error creating Pending_Sign: " << ec.message() << "\n";
        return;
    }

    fs::path manifestPath = pendingDir / "manifest.json";

    std::vector<ManifestEntry> entries;
    size_t scanned = 0, unsigned_ = 0, errors = 0;

    std::cout << "Scanning...\n";

    for (auto it = fs::recursive_directory_iterator(
        targetDir,
        fs::directory_options::skip_permission_denied, ec);
        it != fs::recursive_directory_iterator(); ++it)
    {
        if (ec) { ec.clear(); continue; }

        const auto& entry = *it;

        // Skip Pending_Sign itself
        if (entry.path().parent_path() == pendingDir ||
            entry.path() == pendingDir)
        {
            it.disable_recursion_pending();
            continue;
        }

        if (!entry.is_regular_file(ec)) continue;
        if (!IsPEExtension(entry.path())) continue;

        ++scanned;

        int  sigCount  = 0;
        bool testSig   = false;
        try
        {
            sigCount = IsFileSigned(entry.path());
            if (sigCount > 0)
                testSig = HasTestSignature(entry.path());
        }
        catch (...)
        {
            std::cerr << "  [WARN] Could not check signature: "
                << w2u(entry.path().wstring()) << "\n";
            ++errors;
            continue;
        }

        if (sigCount == 0 || testSig)
        {
            ++unsigned_;
            std::string filename = w2u(entry.path().filename().wstring());
            std::string origFull = w2u(entry.path().wstring());
            std::string origRel  = w2u(entry.path().lexically_relative(targetDir).wstring());

            const char* tag = testSig ? "[TEST SIGNED]" : "[UNSIGNED]   ";

            try
            {
                auto [dest, relPath] = ResolveDestination(pendingDir, filename);
                fs::copy_file(entry.path(), dest, fs::copy_options::overwrite_existing, ec);
                if (ec)
                {
                    std::cerr << "  [ERROR] Copy failed for " << origRel
                        << ": " << ec.message() << "\n";
                    ++errors;
                    --unsigned_;
                    continue;
                }
                entries.push_back({ relPath, origFull });
                std::cout << "  " << tag << " " << origRel << "\n"
                    << "         -> Pending_Sign/" << relPath << "\n";
            }
            catch (const std::exception& ex)
            {
                std::cerr << "  [ERROR] " << origRel << ": " << ex.what() << "\n";
                ++errors;
                --unsigned_;
            }
        }
    }

    if (!entries.empty())
    {
        try
        {
            WriteManifest(manifestPath, entries);
            std::cout << "\nManifest written: " << w2u(manifestPath.wstring()) << "\n";
        }
        catch (const std::exception& ex)
        {
            std::cerr << "Error writing manifest: " << ex.what() << "\n";
        }
    }

    std::cout << "\n--- Summary ---\n"
        << "  PE files scanned : " << scanned << "\n"
        << "  Unsigned/test-signed (copied): " << unsigned_ << "\n"
        << "  Errors           : " << errors << "\n";
}
