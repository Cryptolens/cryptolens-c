#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode_base64.h"
#include "response_parser_cJSON.h"
#include "signature_verifier.h"

int
handle_activate_response(error_t * e, signature_verifier_t * signature_verifier, char const* response)
{
  char * license_key_base64 = NULL;
  char * signature_base64 = NULL;

  parse_activate_response(response, &license_key_base64, &signature_base64);

  size_t license_key_len;
  unsigned char * license_key = decode_base64(license_key_base64, &license_key_len);
  size_t signature_len;
  unsigned char * signature = decode_base64(signature_base64, &signature_len);

  int b = verify(e, signature_verifier, license_key, license_key_len, signature, signature_len);

  free(license_key);
  free(signature);
  free(license_key_base64);
  free(signature_base64);

  return b;
}
