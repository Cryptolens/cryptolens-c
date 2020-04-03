#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CRYPTOLENS_COMPILING
#include "cryptolens/error.h"
#include "cryptolens/request_handler.h"

struct cryptolens_RH {
};

struct cryptolens_RHP_builder {
};

typedef struct response {
} response_t;

cryptolens_RH_t *
cryptolens_RH_new(cryptolens_error_t * e)
{
  cryptolens_RH_t * o = NULL;

  if (!cryptolens_check_error(e)) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_DISABLED_API, 0); }

  return o;
}

void
cryptolens_RH_destroy(cryptolens_RH_t * o)
{
}

cryptolens_RHP_builder_t *
cryptolens_RHP_new(cryptolens_error_t *e, cryptolens_RH_t * rh, char const* method)
{
  cryptolens_RHP_builder_t * o = NULL;

  if (!cryptolens_check_error(e)) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_DISABLED_API, 0); }

  return o;
}

void
cryptolens_RHP_destroy(cryptolens_RHP_builder_t * o)
{
}

void
cryptolens_RHP_add_argument(cryptolens_error_t * e, cryptolens_RHP_builder_t * o, char const* key, char const* value)
{
}

char *
cryptolens_RHP_perform(cryptolens_error_t * e, cryptolens_RHP_builder_t * o)
{
  char * response = NULL;

  if (!cryptolens_check_error(e)) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_DISABLED_API, 0); }

  return response;
}
