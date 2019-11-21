#pragma once

#include "../error.h"

void
cryptolens_IN_decode_base64(
  cryptolens_error_t *,
  char const*,
  unsigned char **,
  size_t *
);
