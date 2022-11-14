#pragma once

#include <stdlib.h>
#include "cryptolens.h"

#ifdef __cplusplus
extern "C" {
#endif

char *
cryptolens_MC_get_machine_code(
  cryptolens_error_t * e
);

void
cryptolens_MC_destroy_machine_code(char* machine_code);

#ifdef __cplusplus
}
#endif
