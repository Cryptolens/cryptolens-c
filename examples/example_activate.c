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

  cryptolens_set_modulus_base64(&e, cryptolens, "khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==");
  cryptolens_set_exponent_base64(&e, cryptolens, "AQAB");
  cryptolens_MC_set_machine_code(&e, cryptolens, "289jf2afs3");

  cryptolens_activate(&e, cryptolens, "WyI0NjUiLCJBWTBGTlQwZm9WV0FyVnZzMEV1Mm9LOHJmRDZ1SjF0Vk52WTU0VzB2Il0=", "3646", "MPDWY-PQAOW-FKSCH-SGAAU");

  printf("%s\n", !cryptolens_check_error(&e) ? "Activation was successful!" : "Activation failed!");

  cryptolens_destroy(cryptolens);
}
