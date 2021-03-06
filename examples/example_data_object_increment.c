#include <stdio.h>
#include <stdlib.h>

#include "cryptolens/cryptolens.h"

int
main()
{
  cryptolens_error_t e; cryptolens_reset_error(&e);
  cryptolens_t * cryptolens = cryptolens_init(&e);

  // Increment data object based on data object id
  cryptolens_reset_error(&e);
  cryptolens_DO_increment(
    // Error object
    &e,
    // Cryptolens object
    cryptolens,
    // Token
    "WyIxMjU5OSIsImdXc0drbm1kalZJZXdDYlhqU1g1QXZIbEs5U3ArSGI3c1RUNkdxRVkiXQ==",
    // Data object id
    "8588",
    // Value to add
    "1",
    // Enable bound
    1,
    // Bound
    "10000"
  );
  if (cryptolens_check_error(&e)) { printf("Incrementing data object failed!\n"); }
  else                            { printf("Successfully incremented data object\n"); }

  // Increment data object based on license key and name
  cryptolens_reset_error(&e);
  cryptolens_DO_key_increment(
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
    "asdf",
    // Value to add
    "1",
    // Enable bound
    1,
    // Bound
    "10000"
  );
  if (cryptolens_check_error(&e)) { printf("Incrementing license key data object failed!\n"); }
  else                            { printf("Successfully incremented license key data object\n"); }

  // Increment data object based on machine code and name
  cryptolens_reset_error(&e);
  cryptolens_DO_machine_code_increment(
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
    "asdf",
    // Value to add
    "1",
    // Enable bound
    1,
    // Bound
    "10000"
  );
  if (cryptolens_check_error(&e)) { printf("Incrementing machine code data object failed!\n"); }
  else                            { printf("Successfully incremented machine code data object\n"); }

  cryptolens_destroy(cryptolens);
}
