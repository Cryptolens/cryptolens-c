#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "internal/decode_base64.h"
#include "error.h"

typedef struct cryptolens_signature_verifier_openssl {
  RSA * rsa;
} cryptolens_signature_verifier_t;

cryptolens_signature_verifier_t *
cryptolens_SV_init(
  cryptolens_error_t * e
)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  BIGNUM *n = NULL;
  BIGNUM *exp = NULL;
  int result = 0;
#endif
  cryptolens_signature_verifier_t * x = malloc(sizeof(cryptolens_signature_verifier_t));
  if (x == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, CRYPTOLENS_ER_ALLOC_FAILED, 0); goto error; }

  x->rsa = RSA_new();
  if (x->rsa == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 1, 0); goto error; }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  x->rsa->n = BN_new();
  x->rsa->e = BN_new();

  if (x->rsa->n == NULL || x->rsa->e == NULL) {
    RSA_free(x->rsa);
    free(x);
    x = NULL;

    cryptolens_set_error(e, CRYPTOLENS_ES_SV, 2, 0);
    goto error;
  }
#else
  n = BN_new();
  exp = BN_new();

  if (n == NULL || exp == NULL) {
    RSA_free(x->rsa);
    free(x);
    x = NULL;

    if (n != NULL) { BN_free(n); }
    if (e != NULL) { BN_free(exp); }

    cryptolens_set_error(e, CRYPTOLENS_ES_SV, 3, 0);
    goto error;
  }

  result = RSA_set0_key(x->rsa, n, exp, NULL);
  if (result != 1) {
    BN_free(n);
    BN_free(exp);
    RSA_free(x->rsa);
    free(x);
    x = NULL;

    cryptolens_set_error(e, CRYPTOLENS_ES_SV, 4, 0);
    goto error;
  }
#endif

  goto end;

error:
end:
  return x;
}

void
cryptolens_SV_destroy(
  cryptolens_signature_verifier_t * o
)
{
  if (o) {
    RSA_free(o->rsa);
  }

  free(o);
}

void
cryptolens_SV_set_modulus_base64(
  cryptolens_error_t * e,
  cryptolens_signature_verifier_t * o,
  char const* modulus_base64
)
{
  size_t modulus_len = 0;
  unsigned char * modulus = NULL;

  if (cryptolens_check_error(e)) { goto end; }

  cryptolens_IN_decode_base64(e, modulus_base64, &modulus, &modulus_len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  // Bignum n will be owned by o->rsa. Only bind it to check for error.
  BIGNUM * n = BN_bin2bn(modulus,  modulus_len,  o->rsa->n);
  if (n == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 5, 0); goto error; }
#else
  BIGNUM const* exp_current;

  // void return type
  RSA_get0_key(o->rsa, NULL, &exp_current, NULL);

  BIGNUM * n = BN_bin2bn(modulus,  modulus_len, NULL);
  if (n == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 6, 0); goto error; }

  BIGNUM * exp;
  if (exp_current == NULL) {
    // Requirements for RSA_set0_key() below is that the first time we call it, both n and e must
    // be set. So in case e has not been set we allocate a dummy BIGNUM here and use that.
    exp = BN_new();
    if (exp == NULL) { BN_free(n); cryptolens_set_error(e, CRYPTOLENS_ES_SV, 7, 0); goto error; }
  } else {
    // If e is already set it is owned by o->rsa, and it is not a valid argument to RSA_set0_key()
    exp = NULL;
  }

  int result = RSA_set0_key(o->rsa, n, exp, NULL);
  if (result != 1) { BN_free(n); BN_free(exp); cryptolens_set_error(e, CRYPTOLENS_ES_SV, 8, 0); goto error; }
#endif

  goto end;

error:
end:
  free(modulus);
}

void
cryptolens_SV_set_exponent_base64(
  cryptolens_error_t * e,
  cryptolens_signature_verifier_t * o,
  char const* exponent_base64
)
{
  size_t exponent_len = 0;
  unsigned char * exponent = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  cryptolens_IN_decode_base64(e, exponent_base64, &exponent, &exponent_len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  // Bignum exp will be owned by o->rsa. Only bind it to check for error.
  BIGNUM * exp = BN_bin2bn(exponent, exponent_len, o->rsa->e);
  if (exp == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 9, 0); goto error; }
#else
  BIGNUM const* n_current;

  // void return type
  RSA_get0_key(o->rsa, &n_current, NULL, NULL);

  BIGNUM * exp = BN_bin2bn(exponent,  exponent_len, NULL);
  if (exp == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 10, 0); goto error; }

  BIGNUM * n;
  if (n_current == NULL) {
    // Requirements for RSA_set0_key() below is that the first time we call it, both n and e must
    // be set. So in case n has not been set we allocate a dummy BIGNUM here and use that.
    n = BN_new();
    if (n == NULL) { BN_free(exp); cryptolens_set_error(e, CRYPTOLENS_ES_SV, 11, 0); goto error; }
  } else {
    // If n is already set it is owned by o->rsa, and it is not a valid argument to RSA_set0_key()
    n = NULL;
  }

  int result = RSA_set0_key(o->rsa, n, exp, NULL);
  if (result != 1) { BN_free(n); BN_free(exp); cryptolens_set_error(e, CRYPTOLENS_ES_SV, 12, 0); goto error; }
#endif

  goto end;

error:
end:
  free(exponent);
  return;
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
  int r = 0;
  EVP_MD_CTX * ctx = NULL;
  EVP_PKEY * pkey = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  if (o->rsa == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 13, 0); goto error; }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  ctx = EVP_MD_CTX_create();
#else
  ctx = EVP_MD_CTX_new();
#endif
  if (ctx == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 14, 0); goto error; }

  pkey = EVP_PKEY_new();
  if (pkey == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 15, 0); goto error; }

  r = EVP_PKEY_set1_RSA(pkey, o->rsa);
  if (r != 1) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 16, 0); goto error; }

  r = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
  if (r != 1) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 17, 0); goto error; }

  r = EVP_DigestVerifyUpdate(ctx, message, message_len);
  if (r != 1) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 18, 0); goto error; }

  r = EVP_DigestVerifyFinal(ctx, signature, signature_len);
  if (r != 1) { cryptolens_set_error(e, CRYPTOLENS_ES_SV, 19, 0); goto error; }

  goto end;

error:
  r = 0;
end:
  // Void return type
  EVP_PKEY_free(pkey);

  // Void return type
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  EVP_MD_CTX_destroy(ctx);
#else
  EVP_MD_CTX_free(ctx);
#endif

  return r == 1;
}
