// This file is part of WinGUp project
// Copyright (C)2026 Don HO <don.h@free.fr>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// at your option any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.



/*
    XML Signer - Signs XML files (XMLDSig) using a code-signing certificate from Windows certificate store
    
    Reads configuration from signXmlFile.ini:

    [thumbprint]
    YOUR_CERTIFICATE_THUMBPRINT
    
    [filesToSign]
    c:\your folder\file2sign1.xml
    c:\your folder\file2sign2.xml

    Note that the certificate thumbprint is necessary to find the certificate from the store.
*/

#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <msxml6.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <comutil.h>
#include <algorithm>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "msxml6.lib")

#import <msxml6.dll> exclude("ISequentialStream", "_FILETIME", "IStream", "IErrorInfo") rename_namespace("MSXML6")

using namespace std;

// Convert std::string to std::wstring
wstring s2ws(const string& str)
{
    if (str.empty()) return wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (len == 0) return wstring();
    wstring wstr(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], len);
    return wstr;
}

// Convert std::wstring to std::string
string ws2s(const wstring& wstr)
{
    if (wstr.empty()) return string();
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len == 0) return string();
    string str(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], len, nullptr, nullptr);
    return str;
}

// Encode bytes to Base64
wstring base64Encode(const vector<BYTE>& data)
{
    DWORD dwSize = 0;
    if (!CryptBinaryToStringW(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &dwSize))
    {
        return L"";
    }
    
    wstring result(dwSize - 1, 0);
    if (!CryptBinaryToStringW(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &dwSize))
    {
        return L"";
    }
    
    return result;
}

// Get certificate from store by thumbprint
PCCERT_CONTEXT getCertificateFromStore(const wstring& thumbprint)
{
    // Remove spaces and non-hex chars
    wstring cleanThumbprint;
    for (wchar_t c : thumbprint)
    {
        if (iswxdigit(c))
            cleanThumbprint += c;
    }
    
    // Convert hex string to bytes
    vector<BYTE> thumbprintBytes;
    for (size_t i = 0; i < cleanThumbprint.length(); i += 2)
    {
        wstring byteStr = cleanThumbprint.substr(i, 2);
        BYTE byte = (BYTE)wcstol(byteStr.c_str(), nullptr, 16);
        thumbprintBytes.push_back(byte);
    }
    
    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    
    if (!hStore)
    {
        wcout << L"Failed to open certificate store" << endl;
        return nullptr;
    }
    
    CRYPT_HASH_BLOB hashBlob;
    hashBlob.cbData = (DWORD)thumbprintBytes.size();
    hashBlob.pbData = thumbprintBytes.data();
    
    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SHA1_HASH,
        &hashBlob,
        nullptr);
    
    CertCloseStore(hStore, 0);
    
    if (!pCertContext)
    {
        wcout << L"Certificate not found. Ensure USB token is plugged in." << endl;
        return nullptr;
    }
    
    return pCertContext;
}

// Compute SHA-256 hash using BCrypt
vector<BYTE> computeSHA256(const vector<BYTE>& data)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashSize = 32;
    vector<BYTE> hash(hashSize);
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return vector<BYTE>();
    
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return vector<BYTE>();
    }
    
    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, hash.data(), hashSize, 0);
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return hash;
}

// Sign data using certificate
vector<BYTE> signData(const vector<BYTE>& hash, PCCERT_CONTEXT pCertContext)
{
    NCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwKeySpec = 0;
    BOOL fCallerFreeProvOrNCryptKey = FALSE;
    
    if (!CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &hKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
    {
        wcout << L"Failed to acquire private key" << endl;
        return vector<BYTE>();
    }
    
    // Setup padding info for RSA-SHA256
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    
    // Get signature size
    DWORD cbSignature = 0;
    SECURITY_STATUS status = NCryptSignHash(hKey, &paddingInfo, (PBYTE)hash.data(), (DWORD)hash.size(), NULL, 0, &cbSignature, BCRYPT_PAD_PKCS1);
    
    if (status != 0)
    {
        wcout << L"Failed to get signature size, status: 0x" << hex << status << endl;
        if (fCallerFreeProvOrNCryptKey)
            NCryptFreeObject(hKey);

        return vector<BYTE>();
    }
    
    vector<BYTE> signature(cbSignature);
    
    status = NCryptSignHash(hKey, &paddingInfo, (PBYTE)hash.data(), (DWORD)hash.size(), signature.data(), cbSignature, &cbSignature, BCRYPT_PAD_PKCS1);
    
    if (fCallerFreeProvOrNCryptKey)
        NCryptFreeObject(hKey);
    
    if (status != 0)
    {
        wcout << L"Failed to sign hash, status: 0x" << hex << status << endl;
        return vector<BYTE>();
    }
    
    signature.resize(cbSignature);
    return signature;
}

// Sign XML file
bool signXmlFile(const wstring& xmlPath, PCCERT_CONTEXT pCertContext)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    MSXML6::IXMLDOMDocument3Ptr pXMLDoc;
    
    try
    {
        // Load XML
        hr = pXMLDoc.CreateInstance(__uuidof(MSXML6::DOMDocument60));
        if (FAILED(hr))
        {
            wcout << L"Failed to create XML document" << endl;
            return false;
        }
        
        pXMLDoc->put_preserveWhiteSpace(VARIANT_TRUE);
        pXMLDoc->async = VARIANT_FALSE;
        
        _variant_t vPath(xmlPath.c_str());
        if (pXMLDoc->load(vPath) == VARIANT_FALSE)
        {
            wcout << L"Failed to load XML file: " << xmlPath << endl;
            return false;
        }
        
        // Get root element for computing digest
        MSXML6::IXMLDOMElementPtr pRoot = pXMLDoc->GetdocumentElement();
        
        // Serialize XML to bytes (for digest calculation)
        _bstr_t xmlContent = pXMLDoc->Getxml();
        string xmlStr((char*)xmlContent);
        vector<BYTE> xmlBytes(xmlStr.begin(), xmlStr.end());
        
        // Compute digest of the document
        vector<BYTE> digestValue = computeSHA256(xmlBytes);
        wstring digestValueB64 = base64Encode(digestValue);
        
        // Create SignedInfo element
        wostringstream signedInfoXml;
        signedInfoXml << L"<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
        signedInfoXml << L"<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>";
        signedInfoXml << L"<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod>";
        signedInfoXml << L"<Reference URI=\"\">";
        signedInfoXml << L"<Transforms>";
        signedInfoXml << L"<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>";
        signedInfoXml << L"</Transforms>";
        signedInfoXml << L"<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>";
        signedInfoXml << L"<DigestValue>" << digestValueB64 << L"</DigestValue>";
        signedInfoXml << L"</Reference>";
        signedInfoXml << L"</SignedInfo>";
        
        wstring signedInfoStr = signedInfoXml.str();
        string signedInfoUtf8 = ws2s(signedInfoStr);
        vector<BYTE> signedInfoBytes(signedInfoUtf8.begin(), signedInfoUtf8.end());
        
        // Compute hash of SignedInfo
        vector<BYTE> signedInfoHash = computeSHA256(signedInfoBytes);
        
        // Sign the hash
        vector<BYTE> signatureValue = signData(signedInfoHash, pCertContext);
        if (signatureValue.empty())
        {
            wcout << L"Failed to sign data" << endl;
            return false;
        }
        
        wstring signatureValueB64 = base64Encode(signatureValue);
        
        // Get certificate bytes for embedding
        vector<BYTE> certBytes(pCertContext->pbCertEncoded,
            pCertContext->pbCertEncoded + pCertContext->cbCertEncoded);
        wstring certB64 = base64Encode(certBytes);
        
        // Create Signature element
        wostringstream signatureXml;
        signatureXml << L"<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
        signatureXml << signedInfoStr;
        signatureXml << L"<SignatureValue>" << signatureValueB64 << L"</SignatureValue>";
        signatureXml << L"<KeyInfo>";
        signatureXml << L"<X509Data>";
        signatureXml << L"<X509Certificate>" << certB64 << L"</X509Certificate>";
        signatureXml << L"</X509Data>";
        signatureXml << L"</KeyInfo>";
        signatureXml << L"</Signature>";
        
        // Parse signature as XML node
        MSXML6::IXMLDOMDocument3Ptr pSigDoc;
        hr = pSigDoc.CreateInstance(__uuidof(MSXML6::DOMDocument60));
        if (FAILED(hr))
        {
            wcout << L"Failed to create signature document" << endl;
            return false;
        }
        
        pSigDoc->loadXML(_bstr_t(signatureXml.str().c_str()));
        MSXML6::IXMLDOMNodePtr pSigNode = pSigDoc->GetdocumentElement();
        
        // Import and append to original document
        MSXML6::IXMLDOMNodePtr pImportedNode = pXMLDoc->importNode(pSigNode, VARIANT_TRUE);
        pRoot->appendChild(pImportedNode);
        
        // Save signed file
        wstring signedPath = xmlPath + L".signed";
        _variant_t vSignedPath(signedPath.c_str());
        hr = pXMLDoc->save(vSignedPath);
        
        if (FAILED(hr))
        {
            wcout << L"Failed to save signed file" << endl;
            return false;
        }
        
        wcout << L"Successfully signed: " << xmlPath << endl;
        wcout << L"Saved to: " << signedPath << endl;
        
        return true;
    }
    catch (_com_error& e)
    {
        wcout << L"COM Error: " << e.ErrorMessage() << endl;
        return false;
    }
    catch (...)
    {
        wcout << L"Unexpected error" << endl;
        return false;
    }
}

int main()
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    
    wcout << L"=== XML Signer ===" << endl;
    
    // Read INI file
    wstring iniPath = L"xmlSigner.ini";
    ifstream iniFile(iniPath);
    
    if (!iniFile.is_open())
    {
        wcout << L"Error: " << iniPath << L" not found" << endl;
        wcout << L"Press any key to exit." << endl;
        getchar();
        return 1;
    }
    
    wstring thumbprint;
    vector<wstring> filesToSign;
    string currentSection;
    string line;
    
    while (getline(iniFile, line))
    {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        if (line.empty() || line[0] == ';')
            continue;
        
        if (line[0] == '[' && line[line.length() - 1] == ']')
        {
            currentSection = line;
            transform(currentSection.begin(), currentSection.end(),
                currentSection.begin(), ::tolower);
            continue;
        }
        
        if (currentSection == "[thumbprint]")
        {
            thumbprint = s2ws(line);
        }
        else if (currentSection == "[filestosign]")
        {
            filesToSign.push_back(s2ws(line));
        }
    }
    
    iniFile.close();
    
    if (thumbprint.empty() || filesToSign.empty())
    {
        wcout << L"Error: Missing thumbprint or files in INI file" << endl;
        wcout << L"Press any key to exit." << endl;
        getchar();
        return 1;
    }
    
    wcout << L"Thumbprint: " << thumbprint << endl;
    wcout << L"Files to sign: " << filesToSign.size() << endl << endl;
    
    // Get certificate
    PCCERT_CONTEXT pCert = getCertificateFromStore(thumbprint);
    if (!pCert)
    {
        wcout << L"Failed to get certificate" << endl;
        wcout << L"Press any key to exit." << endl;
        getchar();
        return 1;
    }
    
    // Get subject name
    DWORD dwSize = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
    wstring subjectName(dwSize - 1, 0);
    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &subjectName[0], dwSize);
    
    wcout << L"Certificate found: " << subjectName << endl << endl;
    
    // Sign all files
    int successCount = 0;
    for (const wstring& file : filesToSign)
    {
        wcout << L"Signing: " << file << L"..." << endl;
        
        if (signXmlFile(file, pCert))
        {
            successCount++;
        }
        else
        {
            wcout << L"Failed to sign: " << file << endl;
        }
        
        wcout << endl;
    }
    
    CertFreeCertificateContext(pCert);
    
    wcout << L"=== Summary ===" << endl;
    wcout << L"Successfully signed: " << successCount << L"/" << filesToSign.size() << endl;
    
    wcout << L"Press any key to exit." << endl;
    getchar();
    
    CoUninitialize();
    return 0;
}
