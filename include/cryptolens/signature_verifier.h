#pragma once

#include "error.h"

typedef struct cryptolens_signature_verifier cryptolens_signature_verifier_t;

#ifdef __cplusplus
extern "C" {
#endif

cryptolens_signature_verifier_t *
cryptolens_SV_init(
  cryptolens_error_t *
);

void
cryptolens_SV_destroy(
  cryptolens_signature_verifier_t *
);

void
cryptolens_SV_set_modulus_base64(
  cryptolens_error_t *,
  cryptolens_signature_verifier_t *,
  char const*
);

void
cryptolens_SV_set_exponent_base64(
  cryptolens_error_t *,
  cryptolens_signature_verifier_t *,
  char const*
);

int
cryptolens_SV_verify(
  cryptolens_error_t *,
  cryptolens_signature_verifier_t *,
  unsigned char const*,
  size_t,
  unsigned char const*,
  size_t
);

#ifdef __cplusplus
}
#endif
