#pragma once

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

#ifdef __cplusplus
extern "C" {
#endif

void
cryptolens_DO_destroy(
  cryptolens_DO_t *
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

#ifdef __cplusplus
}
#endif
