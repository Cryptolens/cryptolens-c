#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

void
parse_activate_response(char const* response, char ** messageBase64, char ** signatureBase64)
{
  size_t n;
  cJSON * json = cJSON_Parse(response);
  cJSON * licenseKey = cJSON_GetObjectItemCaseSensitive(json, "licenseKey");
  cJSON * signature = cJSON_GetObjectItemCaseSensitive(json, "signature");

  // TODO: Check result field, and parse error message if necessary

  if (!cJSON_IsString(licenseKey) || !cJSON_IsString(signature)) { /* TODO: Set errors */ }

  n = strlen(licenseKey->valuestring);
  *messageBase64 = malloc(n + 1);
  // TODO: Set error
  strcpy(*messageBase64, licenseKey->valuestring); // TODO: strcpy

  n = strlen(signature->valuestring);
  *signatureBase64 = malloc(n + 1);
  // TODO: Set error
  strcpy(*signatureBase64, signature->valuestring); // TODO: strcpy

  cJSON_Delete(json);
}
