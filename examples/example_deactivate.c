#include <stdio.h>
#include <stdlib.h>

#include "cryptolens/cryptolens.h"
#include "cryptolens/machine_code_computer_static.h"

int
main()
{
  cryptolens_error_t e; cryptolens_reset_error(&e);
  cryptolens_t * cryptolens = cryptolens_init(&e);

  cryptolens_deactivate(&e, cryptolens, "WyIxMzE0NyIsIko5dFpiYVlvbDBUUmtFekp2MTVVTkFKN2dnSGFqTnBwRlE3NERzU1oiXQ==", "5454", "BXCMU-QRXBK-VSADS-BALIV", "asdfasdf");

  if (cryptolens_check_error(&e)) {
    printf("Deactivation failed! Error codes: %d %d %d\n", e.subsystem, e.reason, e.extra);
  } else {
    printf("Deactivation sucessful!\n");
  }

  cryptolens_destroy(cryptolens);
}
