#include <stdio.h>

#include "Windows.h"
#include "wincrypt.h"

typedef struct error { int x; } error_t;

typedef struct signature_verifier {
	HCRYPTPROV hProv;
	HCRYPTKEY hPubKey;
} signature_verifier_t;


int b64_pton(char const*, u_char *, size_t);

// Add create which creates and then let init take pointer and just initialize?
// Then cleanup and destroy or something? Or is this just too much noise?

signature_verifier_t *
init(error_t * e)
{
  signature_verifier_t * o = (signature_verifier_t *)malloc(sizeof(signature_verifier_t));
  if (o == NULL) { /* TODO */ return NULL;  }
  o->hProv = 0;
  o->hPubKey = 0;

  if (!CryptAcquireContext(&(o->hProv), NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    //DWORD code = GetLastError();
    //e.set(api::main(), errors::Subsystem::SignatureVerifier, CRYPT_ACQUIRE_CONTEXT_FAILED, code);
    return NULL;
  }

  return o;
}

void
destroy(signature_verifier_t * o)
{
  if (o->hPubKey) { CryptDestroyKey(o->hPubKey); }
  if (o->hProv)   { CryptReleaseContext(o->hProv, 0); }
}

void
set_exponent_base64(error_t* e, signature_verifier_t* o, char const* exponent_base64)
{
}

void
set_modulus_base64(error_t * e, signature_verifier_t * o, char const* modulus_base64)
{
  size_t const DWORD_MAX = 0xFFFFFFFF;

  size_t modulus_len = 0;
  unsigned char * modulus = NULL;
  size_t blob_len = 0;
  unsigned char * blob = NULL; // Make this into BYTE? Otoh we use sizeof below, so that is based around char. zzZzzZZzZZZZZZzzzZZZZzzzzzZzZZzz

  BLOBHEADER *blobheader = NULL;
  RSAPUBKEY *rsapubkey = NULL;

  modulus_len = b64_pton(modulus_base64, NULL, 0);
  modulus = (unsigned char *)malloc(modulus_len);
  if (modulus == NULL) { goto end; /* TODO: Set error */ }
  b64_pton(modulus_base64, modulus, modulus_len);

  // CryptoAPI assumes things are LSB or whatever, other way around from other people.
  for (size_t i = 0, j = modulus_len; i + 1 < j; ++i, --j) { unsigned char t = modulus[i]; modulus[i] = modulus[j-1]; modulus[j-1] = t; }

  blob_len = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + modulus_len;
  if (blob_len      > DWORD_MAX) { /* TODO: Set error */  goto end; }
  if (modulus_len*8 > DWORD_MAX) { /* TODO: Set error */  goto end; }

  blob = (unsigned char *)malloc(blob_len); // Use calloc?
  if (blob == NULL) { /* TODO: Set error */ goto end; }

  blobheader = (BLOBHEADER *)blob;
  blobheader->bType = PUBLICKEYBLOB;
  blobheader->bVersion = CUR_BLOB_VERSION;
  blobheader->reserved = 0;
  blobheader->aiKeyAlg = CALG_RSA_KEYX;

  rsapubkey = (RSAPUBKEY *)(blob + sizeof(BLOBHEADER));
  rsapubkey->magic = 0x31415352;
  rsapubkey->bitlen = (DWORD)(modulus_len * 8);
  rsapubkey->pubexp = 65537;

  memcpy( blob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY)
        , modulus
        , modulus_len
        );

  if (!CryptImportKey(o->hProv, blob, (DWORD)blob_len, 0, 0, &(o->hPubKey))) {
    DWORD code = GetLastError();
    /* TODO: Set error */
    goto end;
  }

end:
  free(blobheader);
  free(modulus);
}

//		basic_Error & e, HCRYPTPROV hProv, HCRYPTKEY hPubKey, std::string const& message, std::string sig)
int
verify(error_t * e, signature_verifier_t * o, unsigned char const* message, size_t message_len, unsigned char const* signature, size_t signature_len)
{
  size_t const DWORD_MAX = 0xFFFFFFFF;

//  if (message.size() > DWORD_MAX) { /* TODO: Set error */ goto end; }
//  if (sig.size()     > DWORD_MAX) { /* TODO: Set error */ goto end; }
  char * signature_lsb = (char *)malloc(signature_len);

  // CryptoAPI assumes things are LSB or whatever, other way around from other people.
  for (size_t i = 0; i < signature_len; ++i) { signature_lsb[i] = signature[signature_len - 1 - i]; }

  HCRYPTHASH hHash = 0;  // Initialized following https://docs.microsoft.com/sv-se/windows/win32/seccrypto/example-c-program-signing-a-hash-and-verifying-the-hash-signature
  if (!CryptCreateHash(o->hProv, CALG_SHA_256, 0, 0, &hHash)) {
    DWORD code = GetLastError();
//    TODO: e.set(api, Subsystem::SignatureVerifier, CRYPT_CREATE_HASH_FAILED, code);
    goto end;
  }

  if (!CryptHashData(hHash, message, message_len, 0)) {
    DWORD code = GetLastError();
// TODO:    e.set(api, Subsystem::SignatureVerifier, CRYPT_HASH_DATA_FAILED, code);
    goto end;
  }

  if (!CryptVerifySignature(hHash, signature_lsb, signature_len, o->hPubKey, NULL, 0)) {
    DWORD code = GetLastError();
// TODO:    e.set(api, Subsystem::SignatureVerifier, CRYPT_VERIFY_SIGNATURE_FAILED, code);
    goto end;
  }

  if (hHash) {
	  CryptDestroyHash(hHash);
  }
  return 1;

end:
  if (hHash) {
    CryptDestroyHash(hHash);
  }

  return 0;
}

#if 0
/**
 * This function is used internally by the library and need not be called.
 */
bool
SignatureVerifier_CryptoAPI::verify_message
  (basic_Error & e
  , std::string const& message
  , std::string const& signature_base64
  )
  const
{
  if (e) { return false; }
  if (!hProv_ || !hPubKey_) { e.set(api::main(), errors::Subsystem::SignatureVerifier, SIGNATURE_VERIFIER_UNINITIALIZED); return false; }

  optional<std::string> sig = internal::b64_decode(signature_base64);
  if (!sig) { e.set(api::main(), errors::Subsystem::Base64); return false; }

  verify(e, hProv_, hPubKey_, message, *sig);
  if (e) { return false; }

  return true;
}

} // namespace v20190401

} // namespace cryptolens_io

void
verify(basic_Error & e, HCRYPTPROV hProv, HCRYPTKEY hPubKey, std::string const& message, std::string sig)
{
  constexpr size_t DWORD_MAX = 0xFFFFFFFF;

//  if (message.size() > DWORD_MAX) { /* TODO: Set error */ goto end; }
//  if (sig.size()     > DWORD_MAX) { /* TODO: Set error */ goto end; }

  // CryptoAPI assumes things are LSB or whatever, other way around from other people.
  // Wtf... detta förstör ju signaturen? herregud, vad håller man på med...?
  for (size_t i = 0, j = sig.size() - 1; i < j; ++i, --j) { std::swap(sig[i], sig[j]); }

  HCRYPTHASH hHash = 0;  // Initialized following https://docs.microsoft.com/sv-se/windows/win32/seccrypto/example-c-program-signing-a-hash-and-verifying-the-hash-signature
  if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
    DWORD code = GetLastError();
    e.set(api, Subsystem::SignatureVerifier, CRYPT_CREATE_HASH_FAILED, code);
    goto end;
  }

  if (!CryptHashData(hHash, (const BYTE*)message.c_str(), (DWORD)message.size(), 0)) {
    DWORD code = GetLastError();
    e.set(api, Subsystem::SignatureVerifier, CRYPT_HASH_DATA_FAILED, code);
    goto end;
  }

  if (!CryptVerifySignature(hHash, (const BYTE*)sig.c_str(), (DWORD)sig.size(), hPubKey, NULL, 0)) {
    DWORD code = GetLastError();
    e.set(api, Subsystem::SignatureVerifier, CRYPT_VERIFY_SIGNATURE_FAILED, code);
    goto end;
  }

end:
  if (hHash) {
    CryptDestroyHash(hHash);
  }
}

#endif
