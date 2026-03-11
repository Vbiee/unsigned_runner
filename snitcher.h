#pragma once
//
// snitcher.h
// Scans a directory and reports unsigned PE files without collecting them.
// Special rule: .sys files must be signed by Microsoft specifically,
//               any other valid signer is still flagged.
//

#include "snatcher.h"

// ---------------------------------------------------------------------------
// Check whether a file's leaf signer subject contains "Microsoft"
// (Superseded by IsSignedBy(path, "Microsoft") from auditor.h — kept for reference)
// ---------------------------------------------------------------------------

//inline bool IsSignedByMicrosoft(const fs::path& filePath)
//{
//    std::wstring wpath = filePath.wstring();
//
//    HCERTSTORE hStore = nullptr;
//    HCRYPTMSG  hMsg   = nullptr;
//
//    if (!CryptQueryObject(
//        CERT_QUERY_OBJECT_FILE,
//        wpath.c_str(),
//        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
//        CERT_QUERY_FORMAT_FLAG_BINARY,
//        0, nullptr, nullptr, nullptr,
//        &hStore, &hMsg, nullptr))
//    {
//        return false;
//    }
//
//    bool isMicrosoft = false;
//
//    DWORD signerInfoSize = 0;
//    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);
//
//    if (signerInfoSize > 0)
//    {
//        std::vector<BYTE> buf(signerInfoSize);
//        auto* signerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
//
//        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &signerInfoSize))
//        {
//            CERT_INFO certInfo        = {};
//            certInfo.Issuer           = signerInfo->Issuer;
//            certInfo.SerialNumber     = signerInfo->SerialNumber;
//
//            PCCERT_CONTEXT pCert = CertFindCertificateInStore(
//                hStore,
//                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
//                0,
//                CERT_FIND_SUBJECT_CERT,
//                &certInfo,
//                nullptr);
//
//            if (pCert)
//            {
//                char name[512] = {};
//                CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
//                    0, nullptr, name, sizeof(name));
//                isMicrosoft = (std::string(name).find("Microsoft") != std::string::npos);
//                CertFreeCertificateContext(pCert);
//            }
//        }
//    }
//
//    CryptMsgClose(hMsg);
//    CertCloseStore(hStore, 0);
//
//    return isMicrosoft;
//}

// ---------------------------------------------------------------------------
// Option 3 – Scan & Report (no file collection)
// ---------------------------------------------------------------------------

inline void RunScanAndReport()
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

    size_t scanned = 0, flagged = 0, errors = 0;

    std::cout << "Scanning...\n";

    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(
        targetDir,
        fs::directory_options::skip_permission_denied, ec);
        it != fs::recursive_directory_iterator(); ++it)
    {
        if (ec) { ec.clear(); continue; }

        const auto& entry = *it;

        // Skip Pending_Sign
        if (entry.path().parent_path() == pendingDir ||
            entry.path() == pendingDir)
        {
            it.disable_recursion_pending();
            continue;
        }

        if (!entry.is_regular_file(ec)) continue;
        if (!IsPEExtension(entry.path())) continue;

        ++scanned;

        std::string ext = entry.path().extension().string();
        for (auto& c : ext) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        bool isSys = (ext == ".sys");

        std::string origRel = w2u(entry.path().lexically_relative(targetDir).wstring());

        try
        {
            int sigCount = IsFileSigned(entry.path());

            if (sigCount == 0)
            {
                ++flagged;
                std::cout << "  [UNSIGNED]      " << origRel << "\n";
            }
            else if (isSys && !IsSignedBy(entry.path(), "Microsoft"))
            {
                ++flagged;
                std::cout << "  [NOT MICROSOFT] " << origRel << "\n";
            }
        }
        catch (...)
        {
            std::cerr << "  [WARN] Could not check signature: " << origRel << "\n";
            ++errors;
        }
    }

    std::cout << "\n--- Summary ---\n"
        << "  PE files scanned : " << scanned << "\n"
        << "  Flagged          : " << flagged << " (unsigned or .sys not by Microsoft)\n"
        << "  Errors           : " << errors << "\n";
}
