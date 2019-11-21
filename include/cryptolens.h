#pragma once

#include "error.h"
#include "machine_code_computer.h"
#include "request_handler.h"
#include "response_parser.h"
#include "signature_verifier.h"

typedef struct cryptolens {
  cryptolens_RH_t * rh;
  cryptolens_signature_verifier_t * signature_verifier;
} cryptolens_t;

typedef struct cryptolens_DO {
  int id;
  char const* name;
  char const* string_value;
  int int_value;
} cryptolens_DO_t;

cryptolens_t *
cryptolens_init(
  cryptolens_error_t *
);

void
cryptolens_destroy(
  cryptolens_t * o
);

void
cryptolens_DO_destroy(
  cryptolens_DO_t *
);

void *
cryptolens_handle_activate_response(
  cryptolens_error_t *,
  cryptolens_signature_verifier_t *,
  char const* 
);

void
cryptolens_activate(
  cryptolens_error_t *,
  cryptolens_t *,
  char const*,
  char const*,
  char const*
);

void
cryptolens_set_modulus_base64(
  cryptolens_error_t *,
  cryptolens_t *,
  char const*
);

void
cryptolens_set_exponent_base64(
  cryptolens_error_t *,
  cryptolens_t *,
  char const*
);


int
cryptolens_DO_global_add(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates,

  cryptolens_DO_t *
);

int
cryptolens_DO_product_add(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* product_id,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates,

  cryptolens_DO_t *
);

int
cryptolens_DO_key_add(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* product_id,
  char const* key,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates,

  cryptolens_DO_t *
);

int
cryptolens_DO_machine_code_add(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* product_id,
  char const* key,
  char const* machine_code,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates,

  cryptolens_DO_t *
);

void
cryptolens_DO_increment(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* id,

  char const* int_value,
  int enable_bound,
  char const* bound
);

void
cryptolens_DO_key_increment(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* product_id,
  char const* key,
  char const*,

  char const* int_value,
  int enable_bound,
  char const* bound
);

void
cryptolens_DO_machine_code_increment(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* product_id,
  char const* key,
  char const* machine_code,
  char const*,

  char const* int_value,
  int enable_bound,
  char const* bound
);

void
cryptolens_DO_decrement(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* id,

  char const* int_value,
  int enable_bound,
  char const* bound
);

void
cryptolens_DO_key_decrement(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* product_id,
  char const* key,
  char const*,

  char const* int_value,
  int enable_bound,
  char const* bound
);

void
cryptolens_DO_machine_code_decrement(
  cryptolens_error_t * e,
  cryptolens_t * rh,
  char const* token,

  char const* product_id,
  char const* key,
  char const* machine_code,
  char const*,

  char const* int_value,
  int enable_bound,
  char const* bound
);

void
cryptolens_IN_activate(
  cryptolens_error_t *,
  cryptolens_RH_t *,
  cryptolens_signature_verifier_t *,
  char const*,
  char const*,
  char const*
);
