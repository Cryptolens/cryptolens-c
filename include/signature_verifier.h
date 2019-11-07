#pragma once

typedef struct error { int x; }  error_t;
typedef void signature_verifier_t;

signature_verifier_t * init(error_t *);

void destroy(signature_verifier_t *);

void set_modulus_base64(error_t *, signature_verifier_t *, char const*);

void set_exponent_base64(error_t *, signature_verifier_t *, char const*);

int verify(error_t *, signature_verifier_t *, unsigned char const*, size_t, unsigned char const*, size_t);
