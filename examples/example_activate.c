#include <stdio.h>
#include <stdlib.h>

#include "cryptolens.h"
#include "machine_code_computer_static.h"

int
main()
{
  cryptolens_error_t e;
  cryptolens_reset_error(&e);
  cryptolens_t * cryptolens = cryptolens_init(&e);
  cryptolens_LK_t * license_key = NULL;

  cryptolens_set_modulus_base64(&e, cryptolens, "khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==");
  cryptolens_set_exponent_base64(&e, cryptolens, "AQAB");
  cryptolens_MC_set_machine_code(&e, cryptolens, "asdfasdf");

  license_key = cryptolens_activate(&e, cryptolens, "WyIxMzE0NyIsIko5dFpiYVlvbDBUUmtFekp2MTVVTkFKN2dnSGFqTnBwRlE3NERzU1oiXQ==", "5454", "BXCMU-QRXBK-VSADS-BALIV", NULL);

  if (cryptolens_check_error(&e)) {
    printf("Activation failed! Error codes: %d %d %d\n", e.subsystem, e.reason, e.extra);
  } else {
    printf("Activation was successful! Expires at %lld\nF1: %d  F2: %d    F3: %d    F4: %d    F5: %d    F6: %d    F7: %d  F8: %d\n",
      license_key->expires, license_key->f1, license_key->f2, license_key->f3, license_key->f4, license_key->f5, license_key->f6, license_key->f7, license_key->f8
    );
  }

  cryptolens_LK_destroy(license_key);
  cryptolens_destroy(cryptolens);
}
