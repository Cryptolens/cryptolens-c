#pragma once

typedef struct cryptolens cryptolens_t;
typedef struct cryptolens_DO cryptolens_DO_t;
typedef struct cryptolens_DOL_entry cryptolens_DOL_entry_t;
typedef struct cryptolens_LK cryptolens_LK_t;

#include "error.h"
#include "machine_code_computer.h"
#include "request_handler.h"
#include "response_parser.h"
#include "signature_verifier.h"

struct cryptolens {
  cryptolens_RH_t * rh;
  cryptolens_signature_verifier_t * signature_verifier;
};

struct cryptolens_LK {
  int product_id;
  int id; // May be missing
  char * key;
  long long created;
  long long expires;
  int period;
  int f1;
  int f2;
  int f3;
  int f4;
  int f5;
  int f6;
  int f7;
  int f8;
  char * notes;
  int block;
  long long global_id;
  void * customer;
  void * activated_machines;
  int trial_activation;
  long long maxnoofmachines;
  void * allowed_machines;
  void * data_objects;
  long long sign_date;
};

struct cryptolens_DO {
  int id;
  char * name;
  char * string_value;
  int int_value;
};

struct cryptolens_DOL_entry {
  cryptolens_DO_t data_object;
  cryptolens_DOL_entry_t * next;
  cryptolens_DOL_entry_t * prev;
  int referencer_type;
  int referencer_id;
};

cryptolens_t *
cryptolens_init(
  cryptolens_error_t *
);

void
cryptolens_destroy(
  cryptolens_t * o
);

void
cryptolens_LK_destroy(
  cryptolens_LK_t *
);

void
cryptolens_DO_destroy(
  cryptolens_DO_t *
);

cryptolens_LK_t *
cryptolens_handle_activate_response(
  cryptolens_error_t *,
  cryptolens_signature_verifier_t *,
  char const* 
);

cryptolens_LK_t *
cryptolens_activate(
  cryptolens_error_t *,
  cryptolens_t *,
  char const*,
  char const*,
  char const*,
  char const*
);

void
cryptolens_deactivate(
  cryptolens_error_t *,
  cryptolens_t *,
  char const*,
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

cryptolens_DOL_entry_t *
cryptolens_DO_all_list(
  cryptolens_error_t *,
  cryptolens_t *,
  char const* token,

  char const* contains
);

cryptolens_DOL_entry_t *
cryptolens_DO_global_list(
  cryptolens_error_t *,
  cryptolens_t *,
  char const* token,

  char const* contains
);

void
cryptolens_DOL_destroy(cryptolens_DOL_entry_t *);

cryptolens_DOL_entry_t *
cryptolens_DO_product_list(
  cryptolens_error_t *,
  cryptolens_t *,
  char const* token,

  char const* product_id,
  char const* contains
);

cryptolens_DOL_entry_t *
cryptolens_DO_key_id_list(
  cryptolens_error_t *,
  cryptolens_t *,
  char const* token,

  char const* key_id,
  char const* contains
);

cryptolens_DOL_entry_t *
cryptolens_DO_key_list(
  cryptolens_error_t *,
  cryptolens_t *,
  char const* token,

  char const* product_id,
  char const* key,
  char const* contains
);

cryptolens_DOL_entry_t *
cryptolens_DO_machine_code_list(
  cryptolens_error_t *,
  cryptolens_t *,
  char const* token,

  char const* product_id,
  char const* key,
  char const* machine_code,
  char const* contains
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

cryptolens_LK_t *
cryptolens_IN_activate(
  cryptolens_error_t *,
  cryptolens_RH_t *,
  cryptolens_signature_verifier_t *,
  char const*,
  char const*,
  char const*,
  char const*
);

void
cryptolens_IN_deactivate(
  cryptolens_error_t *,
  cryptolens_RH_t *,
  char const*,
  char const*,
  char const*,
  char const*
);
