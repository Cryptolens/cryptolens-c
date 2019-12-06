#include <stdio.h>
#include <stdlib.h>

#include "cryptolens.h"

int
main()
{
  cryptolens_error_t e;
  cryptolens_t * cryptolens = cryptolens_init(&e);

  // Decrement data object based on data object id
  cryptolens_reset_error(&e);
  cryptolens_DO_decrement(
    // Error object
    &e,
    // Cryptolens object
    cryptolens,
    // Token
    "WyIxMzE0MCIsInJsc2JoeTBnNWN5M29sY1hqVXdJN29jaWlaM05sbTZzTFBWR3IwQk4iXQ==",
    // Data object id
    "8588",
    // Value to add
    "1",
    // Enable bound
    1,
    // Bound
    "-10000"
  );
  if (cryptolens_check_error(&e)) { printf("Decrementing data object failed!\n"); }
  else                            { printf("Successfully decremented data object\n"); }

  // Decrement data object based on license key and name
  cryptolens_reset_error(&e);
  cryptolens_DO_key_decrement(
    // Error object
    &e,
    // Cryptolens object
    cryptolens,
    // Token
    "WyIxMzE0MCIsInJsc2JoeTBnNWN5M29sY1hqVXdJN29jaWlaM05sbTZzTFBWR3IwQk4iXQ==",
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
    "-10000"
  );
  if (cryptolens_check_error(&e)) { printf("Decrementing license key data object failed!\n"); }
  else                            { printf("Successfully decremented license key data object\n"); }

  // Decrement data object based on machine code and name
  cryptolens_reset_error(&e);
  cryptolens_DO_machine_code_decrement(
    // Error object
    &e,
    // Cryptolens object
    cryptolens,
    // Token
    "WyIxMzE0MCIsInJsc2JoeTBnNWN5M29sY1hqVXdJN29jaWlaM05sbTZzTFBWR3IwQk4iXQ==",
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
    "-10000"
  );
  if (cryptolens_check_error(&e)) { printf("Decrementing machine code data object failed!\n"); }
  else                            { printf("Successfully decremented machine code data object\n"); }

  cryptolens_destroy(cryptolens);
}
