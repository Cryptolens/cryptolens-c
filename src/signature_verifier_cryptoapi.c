#include <stdio.h>

#include "cryptolens/cryptolens.h"

#include "Windows.h"
#include "wincrypt.h"

struct cryptolens_signature_verifier {
  HCRYPTPROV hProv;
  HCRYPTKEY hPubKey;
};


cryptolens_signature_verifier_t *
cryptolens_SV_init(
  cryptolens_error_t * e
)
{
  cryptolens_signature_verifier_t* o = NULL;

  if (cryptolens_check_error(e)) { goto error; }
	  
  o = (cryptolens_signature_verifier_t*)malloc(sizeof(cryptolens_signature_verifier_t));
  if (o == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, CRYPTOLENS_ER_ALLOC_FAILED, 1); goto error;  }

  o->hProv = 0;
  o->hPubKey = 0;

  if (!CryptAcquireContext(&(o->hProv), NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    cryptolens_set_error(e, CRYPTOLENS_ES_SV, 1, 0);
    goto error;
  }

  goto end;

error:
    free(o);
    o = NULL;

end:
  return o;
}


void
cryptolens_SV_destroy(
  cryptolens_signature_verifier_t * o
)
{
  if (o) {
    if (o->hPubKey) { CryptDestroyKey(o->hPubKey); }
    if (o->hProv)   { CryptReleaseContext(o->hProv, 0); }
  }
  free(o);
}

void
cryptolens_SV_set_exponent_base64(
  cryptolens_error_t * e,
  cryptolens_signature_verifier_t * o,
  char const* exponent_base64
)
{
}

void
cryptolens_SV_set_modulus_base64(
  cryptolens_error_t * e,
  cryptolens_signature_verifier_t * o,
  char const* modulus_base64
)
{
  size_t const DWORD_MAX = 0xFFFFFFFF;

  size_t modulus_len = 0;
  unsigned char * modulus = NULL;
  size_t blob_len = 0;
  unsigned char * blob = NULL; // Make this into BYTE? Otoh we use sizeof below, so that is based around char. zzZzzZZzZZZZZZzzzZZZZzzzzzZzZZzz

  BLOBHEADER *blobheader = NULL;
  RSAPUBKEY *rsapubkey = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  cryptolens_IN_decode_base64(e, modulus_base64, &modulus, &modulus_len);
  if (cryptolens_check_error(e)) { goto error; }
#if 0
  modulus_len = b64_pton(modulus_base64, NULL, 0);
  modulus = (unsigned char *)malloc(modulus_len);
  if (modulus == NULL) { cryptolens_set_error(5, X, 0); goto end; }
  b64_pton(modulus_base64, modulus, modulus_len);
#endif

  // CryptoAPI assumes things are LSB or whatever, other way around from other people.
  for (size_t i = 0, j = modulus_len; i + 1 < j; ++i, --j) { unsigned char t = modulus[i]; modulus[i] = modulus[j-1]; modulus[j-1] = t; }

  blob_len = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + modulus_len;
  if (blob_len      > DWORD_MAX) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 2, 0); goto error; }
  if (modulus_len*8 > DWORD_MAX) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 3, 0); goto error; }

  blob = (unsigned char *)malloc(blob_len);
  if (blob == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, CRYPTOLENS_ER_ALLOC_FAILED, 2); goto error; }

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
    cryptolens_set_error(e, CRYPTOLENS_ES_SV, 4, code);
    goto error;
  }

  goto end;

error:
end:
  free(blob);
  free(modulus);
}


int
cryptolens_SV_verify(
  cryptolens_error_t * e,
  cryptolens_signature_verifier_t * o,
  unsigned char const* message,
  size_t message_len,
  unsigned char const* signature,
  size_t signature_len
)
{
  size_t const DWORD_MAX = 0xFFFFFFFF;
  int result = 0;
  unsigned char * signature_lsb = NULL;
  HCRYPTHASH hHash = 0;  // Initialized following https://docs.microsoft.com/sv-se/windows/win32/seccrypto/example-c-program-signing-a-hash-and-verifying-the-hash-signature

  if (cryptolens_check_error(e)) { goto error; }

  if (message_len > DWORD_MAX) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 5, 0); goto error; }
  if (signature_len > DWORD_MAX) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 6, 0); goto error; }

  signature_lsb = (unsigned char *)malloc(signature_len);
  if (signature_lsb == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, CRYPTOLENS_ER_ALLOC_FAILED, 3); goto error; }

  // CryptoAPI assumes things are LSB or whatever, other way around from other people.
  for (size_t i = 0; i < signature_len; ++i) { signature_lsb[i] = signature[signature_len - 1 - i]; }

  if (!CryptCreateHash(o->hProv, CALG_SHA_256, 0, 0, &hHash)) {
    DWORD code = GetLastError();
    cryptolens_set_error(e, CRYPTOLENS_ES_SV, 7, code);
    goto error;
  }

  if (!CryptHashData(hHash, message, message_len, 0)) {
    DWORD code = GetLastError();
    cryptolens_set_error(e, CRYPTOLENS_ES_SV, 8, code);
    goto error;
  }

  if (!CryptVerifySignature(hHash, signature_lsb, signature_len, o->hPubKey, NULL, 0)) {
    DWORD code = GetLastError();
    cryptolens_set_error(e, CRYPTOLENS_ES_SV, 9, code);
    goto error;
  }

  result = 1;

  goto end;

error:
end:
  free(signature_lsb);
  if (hHash) { CryptDestroyHash(hHash); }

  return result;
}
