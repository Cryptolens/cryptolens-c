#include <stdlib.h>
#include <stdio.h>

#include "cryptolens.h"

static
int
add_core(
  cryptolens_error_t * e,
  cryptolens_RHP_builder_t * r,
  char const* token,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates
)
{
  int data_object = -1;

  cryptolens_RHP_add_argument(e, r, "token", token);
  cryptolens_RHP_add_argument(e, r, "Name", name);
  cryptolens_RHP_add_argument(e, r, "StringValue", string_value);
  cryptolens_RHP_add_argument(e, r, "IntValue", int_value);
  cryptolens_RHP_add_argument(e, r, "CheckForDuplicates", check_for_duplicates ? "true" : "false");
  cryptolens_RHP_add_argument(e, r, "v", "1");

  char * response = cryptolens_RHP_perform(e, r);

  data_object = cryptolens_RP_parse_DO_add(e, NULL, response);

  free(response);
  cryptolens_RHP_destroy(r);

  return data_object;
}

int
cryptolens_DO_global_add(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates,

  cryptolens_DO_t * out
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/AddDataObject");

  cryptolens_RHP_add_argument(e, r, "ReferencerType", "0");
  return add_core(e, r, token, name, string_value, int_value, check_for_duplicates);
}

int
cryptolens_DO_product_add(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* product_id,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates,

  cryptolens_DO_t * out
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/AddDataObject");

  cryptolens_RHP_add_argument(e, r, "ReferencerType", "1");
  cryptolens_RHP_add_argument(e, r, "ReferencerId", product_id);
  return add_core(e, r, token, name, string_value, int_value, check_for_duplicates);
}

int
cryptolens_DO_key_add(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* product_id,
  char const* key,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates,

  cryptolens_DO_t * out
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/AddDataObjectToKey");

  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  return add_core(e, r, token, name, string_value, int_value, check_for_duplicates);
}

int
cryptolens_DO_machine_code_add(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* product_id,
  char const* key,
  char const* machine_code,

  char const* name,
  char const* string_value,
  char const* int_value,
  int check_for_duplicates,

  cryptolens_DO_t * out
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/AddDataObjectToMachineCode");

  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "MachineCode", machine_code);
  return add_core(e, r, token, name, string_value, int_value, check_for_duplicates);
}

// -------------------

static
void
additive_core(
  cryptolens_error_t * e,
  cryptolens_RHP_builder_t * r,
  char const* token,

  char const* int_value,
  int enable_bound,
  char const* bound
)
{
  cryptolens_RHP_add_argument(e, r, "token", token);
  cryptolens_RHP_add_argument(e, r, "IntValue", int_value);
  cryptolens_RHP_add_argument(e, r, "EnableBound", enable_bound ? "true" : "false");
  cryptolens_RHP_add_argument(e, r, "Bound", bound);
  cryptolens_RHP_add_argument(e, r, "v", "1");

  char * response = cryptolens_RHP_perform(e, r);

  cryptolens_RP_parse_DO_additive(e, NULL, response);

  free(response);
  cryptolens_RHP_destroy(r);
}

// -------------------

void
cryptolens_DO_increment(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* id,

  char const* int_value,
  int enable_bound,
  char const* bound
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/IncrementIntValue");

  cryptolens_RHP_add_argument(e, r, "Id", id);
  additive_core(e, r, token, int_value, enable_bound, bound);
}

void
cryptolens_DO_key_increment(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* product_id,
  char const* key,
  char const* name,

  char const* int_value,
  int enable_bound,
  char const* bound
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/IncrementIntValueToKey");

  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "Name", name);
  additive_core(e, r, token, int_value, enable_bound, bound);
}

void
cryptolens_DO_machine_code_increment(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* product_id,
  char const* key,
  char const* machine_code,
  char const* name,

  char const* int_value,
  int enable_bound,
  char const* bound
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/IncrementIntValueToMachineCode");

  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "MachineCode", machine_code);
  cryptolens_RHP_add_argument(e, r, "Name", name);
  additive_core(e, r, token, int_value, enable_bound, bound);
}

// -------------------

void
cryptolens_DO_decrement(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* id,

  char const* int_value,
  int enable_bound,
  char const* bound
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/DecrementIntValue");

  cryptolens_RHP_add_argument(e, r, "Id", id);
  additive_core(e, r, token, int_value, enable_bound, bound);
}

void
cryptolens_DO_key_decrement(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* product_id,
  char const* key,
  char const* name,

  char const* int_value,
  int enable_bound,
  char const* bound
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/DecrementIntValueToKey");

  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "Name", name);
  additive_core(e, r, token, int_value, enable_bound, bound);
}

void
cryptolens_DO_machine_code_decrement(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,

  char const* product_id,
  char const* key,
  char const* machine_code,
  char const* name,

  char const* int_value,
  int enable_bound,
  char const* bound
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/DecrementIntValueToMachineCode");

  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "MachineCode", machine_code);
  cryptolens_RHP_add_argument(e, r, "Name", name);
  additive_core(e, r, token, int_value, enable_bound, bound);
}

// -------------------

static
void
list_core(
  cryptolens_error_t * e,
  cryptolens_RHP_builder_t * r
)
{
  cryptolens_RHP_add_argument(e, r, "token", "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==");
  cryptolens_RHP_add_argument(e, r, "v", "1");

  char * response = cryptolens_RHP_perform(e, r);

  printf("%s\n", response ? response : "Response is null");

  free(response);

  cryptolens_RHP_destroy(r);
}

void
cryptolens_DO_product_list(
  cryptolens_error_t * e,
  cryptolens_t * o
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/ListDataObjects");

  cryptolens_RHP_add_argument(e, r, "ReferencerType", "1");
  cryptolens_RHP_add_argument(e, r, "ReferencerId", "5363");
  list_core(e, r);
}

void
cryptolens_DO_key_list(
  cryptolens_error_t * e,
  cryptolens_t * o
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/ListDataObjectsToKey");

  cryptolens_RHP_add_argument(e, r, "ProductId", "5363");
  cryptolens_RHP_add_argument(e, r, "Key", "BZBOR-NDUAC-GQXZR-CVWZX");
  list_core(e, r);
}

void
cryptolens_DO_machine_code_list(
  cryptolens_error_t * e,
  cryptolens_t * o
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, o->rh, "api/data/ListDataObjectsToMachineCode");

  cryptolens_RHP_add_argument(e, r, "ProductId", "5363");
  cryptolens_RHP_add_argument(e, r, "Key", "BZBOR-NDUAC-GQXZR-CVWZX");
  cryptolens_RHP_add_argument(e, r, "MachineCode", "asdfasdf");
  list_core(e, r);
}
