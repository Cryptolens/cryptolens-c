#include <stdio.h>
#include <stdlib.h>

#include "cryptolens/cryptolens.h"
#include "cryptolens/machine_code_computer_static.h"

void
print_data_objects(cryptolens_error_t * e, cryptolens_DOL_entry_t * o)
{
  if (cryptolens_check_error(e)) {
    printf("An error occured while trying to list data objects. Error codes: %d %d %d\n", e->subsystem, e->reason, e->extra);
  } else {
    while (o != NULL) {
      printf("\nId: %d\nName: %s\nInt value: %d\nString value: %s\n", o->data_object.id, o->data_object.name, o->data_object.int_value, o->data_object.string_value);
      o = o->next;
    }
  }
}

int
main()
{
  cryptolens_error_t e; cryptolens_reset_error(&e);
  cryptolens_t * cryptolens = cryptolens_init(&e);
  cryptolens_DOL_entry_t * data_objects = NULL;

  printf("Data objects for product 5363:\n==============================\n");
  cryptolens_reset_error(&e);
  data_objects = cryptolens_DO_product_list(&e, cryptolens, "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==", "5363", "");
  print_data_objects(&e, data_objects);
  cryptolens_DOL_destroy(data_objects);

  printf("\n\nData objects for key with global id 61347:\n==========================================\n");
  cryptolens_reset_error(&e);
  data_objects = cryptolens_DO_key_id_list(&e, cryptolens, "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==", "61347", "");
  print_data_objects(&e, data_objects);
  cryptolens_DOL_destroy(data_objects);

  printf("\n\nData objects for key on product 5363 with key string BZBOR-NDUAC-GQXZR-CVWZX:\n=============================================================================\n");
  cryptolens_reset_error(&e);
  data_objects = cryptolens_DO_key_list(&e, cryptolens, "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==", "5363", "BZBOR-NDUAC-GQXZR-CVWZX", "");
  print_data_objects(&e, data_objects);
  cryptolens_DOL_destroy(data_objects);

  printf("\n\nData objects for machine code asdfasdf on product 5363 and key BZBOR-NDUAC-GQXZR-CVWZX:\n=======================================================================================\n");
  cryptolens_reset_error(&e);
  data_objects = cryptolens_DO_machine_code_list(&e, cryptolens, "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==", "5363", "BZBOR-NDUAC-GQXZR-CVWZX", "asdfasdf", "");
  print_data_objects(&e, data_objects);
  cryptolens_DOL_destroy(data_objects);

  cryptolens_destroy(cryptolens);
}
