// SPDX-License-Identifier: Apache-2.0

#include "fingerprint.hh"
#include <openssl/evp.h>
#include <openssl/sha.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define EVP_MD_CTX_new   EVP_MD_CTX_create
#  define EVP_MD_CTX_free  EVP_MD_CTX_destroy
#endif

std::string Fingerprint::sha256(const unsigned char *data, unsigned int length) {
    unsigned int hashLength = SHA256_DIGEST_LENGTH;
    unsigned char hash[hashLength];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) { 
        return ""; 
    }
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        return "";
    }
    if(1 != EVP_DigestUpdate(mdctx, data, length)) {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLength)) {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    return std::string((char *) hash, SHA256_DIGEST_LENGTH);
}

bool Fingerprint::computeFingerprint(const unsigned char *data, unsigned int length) {
    _bytes = sha256(data, length);
    return true;
}
