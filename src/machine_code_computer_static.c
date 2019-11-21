#include "machine_code_computer.h"
#include "cryptolens.h"

#include <stdlib.h>
#include <string.h>

size_t
strlcpy(char *dst, const char *src, size_t dsize);

static char * machine_code = "";
static int should_free = 0;

char const*
cryptolens_MC_get_machine_code(
  cryptolens_error_t * e
)
{
  return machine_code;
}

void
cryptolens_MC_set_machine_code(
  cryptolens_error_t * e,
  void * DUMMY,
  char const* s
)
{
  if (should_free) { free(machine_code); }

  should_free = 1;
  size_t n = strlen(s) + 1;
  machine_code = malloc(n);
  if (machine_code == NULL) { machine_code = ""; should_free = 0; return; }

  strlcpy(machine_code, s, n);
}
