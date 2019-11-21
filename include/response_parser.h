#pragma once

#include "error.h"

void
cryptolens_RP_parse_activate_response(
  cryptolens_error_t *,
  void *,
  char const*,
  char **,
  char **
);

int
cryptolens_RP_parse_DO_add(
  cryptolens_error_t *,
  void *,
  char const*
);

void
cryptolens_RP_parse_DO_additive(
  cryptolens_error_t *,
  void *,
  char const*
);
