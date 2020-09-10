#pragma once

typedef struct cryptolens cryptolens_t;
typedef struct cryptolens_DO cryptolens_DO_t;
typedef struct cryptolens_DOL_entry cryptolens_DOL_entry_t;
typedef struct cryptolens_LK cryptolens_LK_t;

#include "error.h"
#include "data_objects.h"
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
  cryptolens_DOL_entry_t * data_objects;
  long long sign_date;
};

#ifdef __cplusplus
extern "C" {
#endif

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

cryptolens_LK_t *
cryptolens_activate_floating(
  cryptolens_error_t *,
  cryptolens_t *,
  char const*,
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
cryptolens_deactivate_floating(
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

cryptolens_LK_t *
cryptolens_IN_activate_floating(
  cryptolens_error_t *,
  cryptolens_RH_t *,
  cryptolens_signature_verifier_t *,
  char const*,
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

void
cryptolens_IN_deactivate_floating(
  cryptolens_error_t *,
  cryptolens_RH_t *,
  char const*,
  char const*,
  char const*,
  char const*
);

#ifdef __cplusplus
}
#endif
