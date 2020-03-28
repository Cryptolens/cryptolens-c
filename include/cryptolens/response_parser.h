#pragma once

#include "cryptolens.h"

#ifdef __cplusplus
extern "C" {
#endif

void
cryptolens_RP_parse_activate_response(
  cryptolens_error_t *,
  void *,
  char const*,
  char **,
  char **
);

void
cryptolens_RP_parse_deactivate_response(
  cryptolens_error_t *,
  void *,
  char const*
);

cryptolens_DOL_entry_t *
cryptolens_RP_parse_DO_list(
  cryptolens_error_t *,
  void *,
  char const*
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

cryptolens_LK_t *
cryptolens_RP_parse_license_key(
  cryptolens_error_t *,
  void *,
  char const*
);

#ifdef __cplusplus
}
#endif
