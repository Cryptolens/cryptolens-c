#include <stdlib.h>
#include <string.h>

#include "error.h"

int b64_pton(char const*, unsigned char *, size_t);

void
cryptolens_IN_decode_base64(
  cryptolens_error_t * e,
  char const* s,
  unsigned char **decoded,
  size_t * decoded_len
)
{
  int l = 0;

  if (cryptolens_check_error(e)) { goto end; }

  l = b64_pton(s, NULL, 0);
  if (l < 0) { cryptolens_set_error(e, 3, 1, l); goto end; }

  *decoded_len = l;
  *decoded = (unsigned char *)malloc(*decoded_len);
  if (*decoded == NULL) { *decoded_len = 0; cryptolens_set_error(e, 3, 2, 0); goto end; }

  b64_pton(s, *decoded, *decoded_len);

end:
  return;
}

