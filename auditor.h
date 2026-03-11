#pragma once
//
// auditor.h
// Signature inspection functions for PE files.
//   IsFileSigned      - returns the count of signatures on a file (0 = unsigned)
//   HasTestSignature  - returns true if the file is signed but with an untrusted-root (test) cert
//   IsSignedBy        - returns true if the file has a valid signature from a given company
//

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>

#include <filesystem>
#include <string>
#include <vector>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

namespace fs = std::filesystem;

// OID for nested (dual) signatures stored as unauthenticated attributes
static constexpr char kNestedSigOID[] = "1.3.6.1.4.1.311.2.4.1";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Extracts the leaf signer display names from an already-opened HCERTSTORE /
// HCRYPTMSG pair. Appends results into 'out'.
static void CollectSignerNames(HCERTSTORE hStore, HCRYPTMSG hMsg,
    std::vector<std::string>& out)
{
    DWORD signerCount = 0;
    DWORD paramSize   = sizeof(signerCount);
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0,
            &signerCount, &paramSize))
        return;

    for (DWORD i = 0; i < signerCount; ++i)
    {
        // --- primary signer name ---
        DWORD siSize = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, nullptr, &siSize))
            continue;

        std::vector<BYTE> buf(siSize);
        auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, si, &siSize))
            continue;

        CERT_INFO ci    = {};
        ci.Issuer       = si->Issuer;
        ci.SerialNumber = si->SerialNumber;

        PCCERT_CONTEXT pCert = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);

        if (pCert)
        {
            char name[512] = {};
            CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0, nullptr, name, sizeof(name));
            out.emplace_back(name);
            CertFreeCertificateContext(pCert);
        }

        // --- nested signature signer names ---
        for (DWORD j = 0; j < si->UnauthAttrs.cAttr; ++j)
        {
            if (strcmp(si->UnauthAttrs.rgAttr[j].pszObjId, kNestedSigOID) != 0)
                continue;

            for (DWORD k = 0; k < si->UnauthAttrs.rgAttr[j].cValue; ++k)
            {
                CRYPT_DATA_BLOB blob = {
                    si->UnauthAttrs.rgAttr[j].rgValue[k].cbData,
                    si->UnauthAttrs.rgAttr[j].rgValue[k].pbData
                };

                HCERTSTORE nestedStore = nullptr;
                HCRYPTMSG  nestedMsg   = nullptr;

                if (CryptQueryObject(
                    CERT_QUERY_OBJECT_BLOB, &blob,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0, nullptr, nullptr, nullptr,
                    &nestedStore, &nestedMsg, nullptr))
                {
                    CollectSignerNames(nestedStore, nestedMsg, out);
                    CryptMsgClose(nestedMsg);
                    CertCloseStore(nestedStore, 0);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Returns the total number of signatures on a PE file (primary + nested).
// Returns 0 if the file has no embedded signature at all.
inline int IsFileSigned(const fs::path& filePath)
{
    std::wstring wpath = filePath.wstring();

    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;

    if (!CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, wpath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, nullptr, nullptr, nullptr,
        &hStore, &hMsg, nullptr))
    {
        return 0;
    }

    DWORD signerCount = 0;
    DWORD paramSize   = sizeof(signerCount);
    CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &paramSize);

    int total = static_cast<int>(signerCount);

    // Count nested signatures stored as unauthenticated attributes
    for (DWORD i = 0; i < signerCount; ++i)
    {
        DWORD siSize = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, nullptr, &siSize))
            continue;

        std::vector<BYTE> buf(siSize);
        auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, si, &siSize))
            continue;

        for (DWORD j = 0; j < si->UnauthAttrs.cAttr; ++j)
        {
            if (strcmp(si->UnauthAttrs.rgAttr[j].pszObjId, kNestedSigOID) == 0)
                total += static_cast<int>(si->UnauthAttrs.rgAttr[j].cValue);
        }
    }

    CryptMsgClose(hMsg);
    CertCloseStore(hStore, 0);

    return total;
}

// Returns true if the file has an embedded signature whose signer certificate
// chain ends in an untrusted root — i.e. a test / self-signed certificate that
// has not been installed in the machine's Trusted Root CA store.
// Returns false if the file is unsigned, or if every signer chains to a
// trusted root (production signature).
inline bool HasTestSignature(const fs::path& filePath)
{
    std::wstring wpath = filePath.wstring();

    // Must have an embedded signature blob at all.
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;

    if (!CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, wpath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, nullptr, nullptr, nullptr,
        &hStore, &hMsg, nullptr))
    {
        return false;   // unsigned — no signature at all
    }

    DWORD signerCount = 0;
    DWORD paramSize   = sizeof(signerCount);
    CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &paramSize);

    bool foundTestCert = false;

    for (DWORD i = 0; i < signerCount && !foundTestCert; ++i)
    {
        DWORD siSize = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, nullptr, &siSize))
            continue;

        std::vector<BYTE> buf(siSize);
        auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, si, &siSize))
            continue;

        CERT_INFO ci    = {};
        ci.Issuer       = si->Issuer;
        ci.SerialNumber = si->SerialNumber;

        PCCERT_CONTEXT pLeaf = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);

        if (!pLeaf)
            continue;

        // Build the chain and inspect trust errors.
        CERT_CHAIN_PARA chainPara = {};
        chainPara.cbSize          = sizeof(chainPara);
        PCCERT_CHAIN_CONTEXT pChain = nullptr;

        if (CertGetCertificateChain(
            nullptr,    // default chain engine
            pLeaf,
            nullptr,    // current time
            hStore,
            &chainPara,
            CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
            nullptr,
            &pChain))
        {
            // CERT_TRUST_IS_UNTRUSTED_ROOT means the root CA is not present in
            // the machine's Trusted Root Certification Authorities store —
            // the hallmark of a test / development certificate.
            if (pChain->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT)
                foundTestCert = true;

            CertFreeCertificateChain(pChain);
        }

        CertFreeCertificateContext(pLeaf);
    }

    CryptMsgClose(hMsg);
    CertCloseStore(hStore, 0);

    return foundTestCert;
}

// Returns true if the file has a cryptographically valid signature AND at least
// one signer's subject display name contains 'companyName'.
// Example: IsSignedBy(path, "Microsoft")
inline bool IsSignedBy(const fs::path& filePath, const std::string& companyName)
{
    // Verify signature is actually valid first
    std::wstring wpath = filePath.wstring();

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct       = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath  = wpath.c_str();

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData    = {};
    trustData.cbStruct         = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice       = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice    = WTD_CHOICE_FILE;
    trustData.pFile            = &fileInfo;
    trustData.dwStateAction    = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags      = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGuid, &trustData);

    if (status != ERROR_SUCCESS)
        return false;

    // Collect all signer names (primary + nested) and check for companyName
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;

    if (!CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, wpath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, nullptr, nullptr, nullptr,
        &hStore, &hMsg, nullptr))
    {
        return false;
    }

    std::vector<std::string> names;
    CollectSignerNames(hStore, hMsg, names);

    CryptMsgClose(hMsg);
    CertCloseStore(hStore, 0);

    for (const auto& name : names)
        if (name.find(companyName) != std::string::npos)
            return true;

    return false;
}
