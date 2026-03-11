#pragma once
//
// courier.h
// Finds the Pending_Sign output folder and delivers signed files back to their
// original locations using the manifest written by snatcher.
//

#include "snatcher.h"

// ---------------------------------------------------------------------------
// Minimal JSON parser – just enough for our manifest format
// ---------------------------------------------------------------------------

inline std::vector<ManifestEntry> ParseManifest(const fs::path& manifestPath)
{
    std::ifstream f(manifestPath);
    if (!f) throw std::runtime_error("Cannot open manifest: " + manifestPath.string());

    std::string text((std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());

    std::vector<ManifestEntry> result;
    ManifestEntry cur;

    auto extractStrings = [&](const std::string& src)
        {
            size_t pos = 0;
            auto skipWS = [&]() { while (pos < src.size() && isspace((unsigned char)src[pos])) ++pos; };
            auto readString = [&]() -> std::string
                {
                    if (pos >= src.size() || src[pos] != '"') return {};
                    ++pos;
                    std::string val;
                    while (pos < src.size())
                    {
                        char c = src[pos++];
                        if (c == '\\' && pos < src.size())
                        {
                            char e = src[pos++];
                            switch (e)
                            {
                            case '"':  val += '"';  break;
                            case '\\': val += '\\'; break;
                            case 'n':  val += '\n'; break;
                            case 'r':  val += '\r'; break;
                            case 't':  val += '\t'; break;
                            default:   val += e;   break;
                            }
                        }
                        else if (c == '"') break;
                        else val += c;
                    }
                    return val;
                };

            while (pos < src.size())
            {
                skipWS();
                if (pos >= src.size()) break;
                char c = src[pos];
                if (c == '{')
                {
                    cur = {};
                    ++pos;
                }
                else if (c == '}')
                {
                    if (!cur.relativePath.empty() && !cur.originalPath.empty())
                        result.push_back(cur);
                    ++pos;
                }
                else if (c == '"')
                {
                    std::string key = readString();
                    skipWS();
                    if (pos < src.size() && src[pos] == ':') ++pos;
                    skipWS();
                    std::string val = readString();

                    if (key == "relative_path") cur.relativePath = val;
                    else if (key == "original_path") cur.originalPath = val;
                }
                else ++pos;
            }
        };

    extractStrings(text);
    return result;
}

// ---------------------------------------------------------------------------
// Option 2 – Restore Signed Files
// ---------------------------------------------------------------------------

inline void RunRestoreSigned()
{
    std::string pendingStr;
    std::cout << "Enter path to Pending_Sign folder: ";
    std::getline(std::cin, pendingStr);

    fs::path pendingDir = s2w(pendingStr);
    if (!fs::is_directory(pendingDir))
    {
        std::cerr << "Error: Not a valid directory: " << pendingStr << "\n";
        return;
    }

    // If manifest.json isn't directly here, check for a Pending_Sign subfolder
    if (!fs::exists(pendingDir / "manifest.json"))
    {
        fs::path sub = pendingDir / "Pending_Sign";
        if (fs::is_directory(sub) && fs::exists(sub / "manifest.json"))
        {
            std::cout << "  [INFO] Found Pending_Sign subfolder, using: "
                << w2u(sub.wstring()) << "\n";
            pendingDir = sub;
        }
        else
        {
            std::cerr << "Error: manifest.json not found in " << pendingStr
                << " (also checked Pending_Sign subfolder)\n";
            return;
        }
    }

    fs::path manifestPath = pendingDir / "manifest.json";

    std::vector<ManifestEntry> entries;
    try
    {
        entries = ParseManifest(manifestPath);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Error reading manifest: " << ex.what() << "\n";
        return;
    }

    if (entries.empty())
    {
        std::cout << "Manifest is empty - nothing to restore.\n";
        return;
    }

    size_t restored = 0, skipped = 0, errors = 0;

    fs::path targetDir = pendingDir.parent_path();

    for (const auto& entry : entries)
    {
        fs::path src  = pendingDir / s2w(entry.relativePath);
        fs::path dest = s2w(entry.originalPath);
        std::string origRel = w2u(dest.lexically_relative(targetDir).wstring());

        std::cout << "Restoring: " << entry.relativePath
            << "\n      -> " << origRel << "\n";

        if (!fs::exists(src))
        {
            std::cerr << "  [SKIP] Source not found: " << entry.relativePath << "\n";
            ++skipped;
            continue;
        }

        std::error_code ec;

        fs::create_directories(dest.parent_path(), ec);
        if (ec)
        {
            std::cerr << "  [ERROR] Cannot create parent dir for "
                << origRel << ": " << ec.message() << "\n";
            ++errors;
            continue;
        }

        fs::copy_file(src, dest, fs::copy_options::overwrite_existing, ec);
        if (ec)
        {
            std::cerr << "  [ERROR] Copy failed: " << ec.message() << "\n";
            ++errors;
            continue;
        }

        fs::remove(src, ec);
        if (ec)
            std::cerr << "  [WARN] Could not remove staged copy: " << ec.message() << "\n";

        ++restored;
    }

    // Clean up empty numbered subfolders
    {
        std::error_code ec;
        for (auto& p : fs::directory_iterator(pendingDir, ec))
        {
            if (p.is_directory(ec) && fs::is_empty(p.path(), ec))
                fs::remove(p.path(), ec);
        }
    }

    std::cout << "\n--- Summary ---\n"
        << "  Restored : " << restored << "\n"
        << "  Skipped  : " << skipped << "\n"
        << "  Errors   : " << errors << "\n";
}
