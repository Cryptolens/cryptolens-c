#include <stdio.h>
#include <stdlib.h>

#include "cryptolens.h"

int
main()
{
  cryptolens_error_t e;
  cryptolens_t * cryptolens = cryptolens_init(&e);
  int data_object = -1;

  // Add data object to a product
  cryptolens_reset_error(&e);
  data_object = cryptolens_DO_product_add(
    // Error object
    &e,
    // Cryptolens object
    cryptolens,
    // Token
    "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==",
    // Product id
    "5363",
    // Data object name
    "newdataobject",
    // String value
    "new!",
    // Int value
    "1234",
    // Check for duplicates
    1,
    // Optionally populate a data object struct with the resulting data object
    NULL
  );
  if (cryptolens_check_error(&e)) { printf("Creation of product data object failed!\n"); }
  else                            { printf("Added data object to product with ID: %d\n", data_object); }

  // Add data object to a license key
  cryptolens_reset_error(&e);
  data_object = cryptolens_DO_key_add(
    // Error object
    &e,
    // Cryptolens object
    cryptolens,
    // Token
    "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==",
    // Product id
    "5363",
    // License key
    "BZBOR-NDUAC-GQXZR-CVWZX",
    // Data object name
    "newdataobject",
    // String value
    "new!",
    // Int value
    "1234",
    // Check for duplicates
    1,
    // Optionally populate a data object struct with the resulting data object
    NULL
  );
  if (cryptolens_check_error(&e)) { printf("Creation of license key data object failed!\n"); }
  else                            { printf("Added data object to key with ID: %d\n", data_object); }

  // Add data object to a machine code
  cryptolens_reset_error(&e);
  data_object = cryptolens_DO_machine_code_add(
    // Error object
    &e,
    // Cryptolens object
    cryptolens,
    // Token
    "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==",
    // Product id
    "5363",
    // License key
    "BZBOR-NDUAC-GQXZR-CVWZX",
    // Machine code
    "asdfasdf",
    // Data object name
    "newdataobject",
    // String value
    "new!",
    // Int value
    "1234",
    // Check for duplicates
    1,
    // Optionally populate a data object struct with the resulting data object
    NULL
  );
  if (cryptolens_check_error(&e)) { printf("Creation of machine code data object failed!\n"); }
  else                            { printf("Added data object to machine code with ID: %d\n", data_object); }

  cryptolens_destroy(cryptolens);
}
