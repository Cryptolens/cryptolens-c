#include <stdlib.h>
#include <string.h>

#include "cryptolens/error.h"

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

  if (cryptolens_check_error(e)) { goto error; }

  l = b64_pton(s, NULL, 0);
  if (l < 0) { cryptolens_set_error(e, CRYPTOLENS_ES_BASE64, 4, l); goto error; }

  *decoded_len = l;
  *decoded = (unsigned char *)malloc(*decoded_len+1);
  if (*decoded == NULL) { *decoded_len = 0; cryptolens_set_error(e, CRYPTOLENS_ES_BASE64, CRYPTOLENS_ER_ALLOC_FAILED, 0); goto error; }

  b64_pton(s, *decoded, *decoded_len);
  (*decoded)[*decoded_len] = '\0';

  goto end;

error:
end:
  return;
}
