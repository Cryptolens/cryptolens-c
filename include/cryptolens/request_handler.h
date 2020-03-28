#pragma once

#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cryptolens_RH cryptolens_RH_t;
typedef struct cryptolens_RHP_builder cryptolens_RHP_builder_t;
//#ifdef CRYPTOLENS_COMPILING
#if 1
#else
typedef void cryptolens_RH_t;
typedef void cryptolens_RHP_builder_t;
#endif

cryptolens_RH_t *
cryptolens_RH_new();

void
cryptolens_RH_destroy(cryptolens_RH_t *);

cryptolens_RHP_builder_t *
cryptolens_RHP_new(cryptolens_error_t *, cryptolens_RH_t *, char const*);

void
cryptolens_RHP_destroy(cryptolens_RHP_builder_t *);

void
cryptolens_RHP_add_argument(cryptolens_error_t *, cryptolens_RHP_builder_t *, char const*, char const*);

char *
cryptolens_RHP_perform(cryptolens_error_t *, cryptolens_RHP_builder_t *);

#ifdef __cplusplus
}
#endif
