#include <stdlib.h>
#include <string.h>

int b64_pton(char const*, unsigned char *, size_t);

unsigned char *
decode_base64(char const* s, size_t * len)
{
  unsigned char * decoded = NULL;

  *len = b64_pton(s, NULL, 0);
  decoded = (unsigned char *)malloc(*len);
  if (decoded == NULL) { *len = 0; return NULL; /* TODO: Set error */ }
  b64_pton(s, decoded, *len);
  return decoded;
}

