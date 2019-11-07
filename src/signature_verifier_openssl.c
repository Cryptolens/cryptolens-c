#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "decode_base64.h"

typedef struct error {} error_t;

typedef struct signature_verifier_openssl {
  RSA * rsa;
} signature_verifier_t;


signature_verifier_t *
init(error_t * e)
{
  signature_verifier_t * x = malloc(sizeof(signature_verifier_t));
  if (x == NULL) { goto end; }

  x->rsa = RSA_new();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if (x->rsa != NULL) {
    x->rsa->n = BN_new();
    if (x->rsa->n == NULL) { RSA_free(x->rsa); return; }

    x->rsa->e = BN_new();
    if (x->rsa->e == NULL) { RSA_free(x->rsa); return; }
  }
#else
  if (x->rsa != NULL) {
    BIGNUM *n, *e;
    n = BN_new();
    e = BN_new();

    if (n == NULL || e == NULL) {
      RSA_free(x->rsa);
      x->rsa = NULL;

      if (n != NULL) { BN_free(n); }
      if (e != NULL) { BN_free(e); }
    } else {
      int result = RSA_set0_key(x->rsa, n, e, NULL);
      if (result != 1) { BN_free(n); BN_free(e); RSA_free(x->rsa); x->rsa = NULL; }
    }
  }

#endif

end:
  return x;
}

void
destroy(signature_verifier_t * o)
{
  RSA_free(o->rsa);
  free(o);
}

void
set_modulus_base64(error_t * e, signature_verifier_t * o, char const* modulus_base64)
{
  size_t modulus_len = 0;
  unsigned char * modulus = NULL;

  modulus = decode_base64(modulus_base64, &modulus_len);
#if 0
  modulus_len = b64_pton(modulus_base64, NULL, 0);
  modulus = (unsigned char *)malloc(modulus_len);
  if (modulus == NULL) { goto end; /* TODO: Set error */ }
  b64_pton(modulus_base64, modulus, modulus_len);
#endif


#if OPENSSL_VERSION_NUMBER < 0x10100000L
  // Bignum n will be owned by o->rsa. Only bind it to check for error.
  BIGNUM * n = BN_bin2bn(modulus,  modulus_len,  o->rsa->n);
  if (n == NULL) { goto end; /* TODO: Set error */ }
#else
  BIGNUM const* exp_current;

  // void return type
  RSA_get0_key(o->rsa, NULL, &exp_current, NULL);

  BIGNUM * n = BN_bin2bn(modulus,  modulus_len, NULL);
  if (n == NULL) { goto end; /* TODO: Set error */ }

  BIGNUM * exp;
  if (exp_current == NULL) {
    // Requirements for RSA_set0_key() below is that the first time we call it, both n and e must
    // be set. So in case e has not been set we allocate a dummy BIGNUM here and use that.
    exp = BN_new();
    if (exp == NULL) { BN_free(n); goto end; /* TODO: Set error */ }
  } else {
    // If e is already set it is owned by o->rsa, and it is not a valid argument to RSA_set0_key()
    exp = NULL;
  }

  int result = RSA_set0_key(o->rsa, n, exp, NULL);
  if (result != 1) { BN_free(n); BN_free(exp); goto end; /* TODO: Set error */ }
#endif

end:
  free(modulus);
  return;
}

void
set_exponent_base64(error_t * e, signature_verifier_t * o, char const* exponent_base64)
{
  size_t exponent_len = 0;
  unsigned char * exponent = NULL;

  exponent = decode_base64(exponent_base64, &exponent_len);
#if 0
  exponent_len = b64_pton(exponent_base64, NULL, 0);
  exponent = (unsigned char *)malloc(exponent_len);
  if (exponent == NULL) { goto end; /* TODO: Set error */ }
  b64_pton(exponent_base64, exponent, exponent_len);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  // Bignum exp will be owned by o->rsa. Only bind it to check for error.
  BIGNUM * exp = BN_bin2bn(exponent, exponent_len, o->rsa->e);
  if (exp == NULL) { goto end; /* TODO: Set error */ }
#else
  BIGNUM const* n_current;

  // void return type
  RSA_get0_key(o->rsa, &n_current, NULL, NULL);

  BIGNUM * exp = BN_bin2bn(exponent,  exponent_len, NULL);
  if (exp == NULL) { goto end; /* TODO: Set error */ }

  BIGNUM * n;
  if (n_current == NULL) {
    // Requirements for RSA_set0_key() below is that the first time we call it, both n and e must
    // be set. So in case n has not been set we allocate a dummy BIGNUM here and use that.
    n = BN_new();
    if (n == NULL) { BN_free(exp); goto end; /* TODO: Set error */ }
  } else {
    // If n is already set it is owned by o->rsa, and it is not a valid argument to RSA_set0_key()
    n = NULL;
  }

  int result = RSA_set0_key(o->rsa, n, exp, NULL);
  if (result != 1) { BN_free(n); BN_free(exp); goto end; /* TODO: Set error */ }
#endif

end:
  free(exponent);
  return;
}

int
verify(error_t * e, signature_verifier_t * o, unsigned char const* message, size_t message_len, unsigned char const* signature, size_t signature_len)
{
  int r = 0;
  EVP_MD_CTX * ctx = NULL;
  EVP_PKEY * pkey = NULL;

  if (o->rsa == NULL) { goto end; /* TODO: Set error */ }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  ctx = EVP_MD_CTX_create();
#else
  ctx = EVP_MD_CTX_new();
#endif
  if (ctx == NULL) { goto end; /* TODO: Set error */ }

  pkey = EVP_PKEY_new();
  if (pkey == NULL) { goto end; /* TODO: Set error */ }

  r = EVP_PKEY_set1_RSA(pkey, o->rsa);
  if (r != 1) { goto end; /* TODO: Set error */ }



  r = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
  if (r != 1) { goto end; /* TODO: Set error */ }

  r = EVP_DigestVerifyUpdate(ctx, message, message_len);
  if (r != 1) { goto end; /* TODO: Set error */ }

  r = EVP_DigestVerifyFinal(ctx, signature, signature_len);
  if (r != 1) { goto end; /* TODO: Set error */ }

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
