#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

#include "error.h"


size_t
strlcpy(char *dst, const char *src, size_t dsize);

void
cryptolens_RP_parse_activate_response(
  cryptolens_error_t * e,
  void * o,
  char const* response,
  char ** licenseKeyBase64,
  char ** signatureBase64
)
{
  size_t n;
  cJSON * json = NULL;
  cJSON * result = NULL;
  cJSON * message = NULL;
  cJSON * licenseKey = NULL;
  cJSON * signature = NULL;

  int X = 1234;

  *licenseKeyBase64 = NULL;
  *signatureBase64 = NULL;

  if (cryptolens_check_error(e)) { goto end; }

  json = cJSON_Parse(response);
  if (json == NULL) { cryptolens_set_error(e, 2, 1, 0); goto end; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, 2, X, 0); goto end; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      cryptolens_set_error(e, 2, X, 0);
      goto end;
    }
    cryptolens_set_error(e, 2, X, 0);
    goto end;
  }

  licenseKey = cJSON_GetObjectItemCaseSensitive(json, "licenseKey");
  if (licenseKey == NULL) { cryptolens_set_error(e, 2, X, 0); goto end; }

  signature = cJSON_GetObjectItemCaseSensitive(json, "signature");
  if (signature == NULL) { cryptolens_set_error(e, 2, X, 0); goto end; }

  if (!cJSON_IsString(licenseKey) || !cJSON_IsString(signature)) {
    cryptolens_set_error(e, 2, X, 0);
    goto end;
  }

  n = strlen(licenseKey->valuestring);
  *licenseKeyBase64 = malloc(n + 1);
  if (*licenseKeyBase64 == NULL) { cryptolens_set_error(e, 2, X, 0); goto end; }
  strlcpy(*licenseKeyBase64, licenseKey->valuestring, n+1);

  n = strlen(signature->valuestring);
  *signatureBase64 = malloc(n + 1);
  if (*signatureBase64 == NULL) { cryptolens_set_error(e, 2, X, 0); goto end; }
  strlcpy(*signatureBase64, signature->valuestring, n+1);

end:
  cJSON_Delete(json);

  if (cryptolens_check_error(e)) {
    free(*licenseKeyBase64);
    free(*signatureBase64);

    *licenseKeyBase64 = NULL;
    *signatureBase64 = NULL;
  }
}

// TODO: Should return the newly created data object
int
cryptolens_RP_parse_DO_add(
  cryptolens_error_t * e,
  void * o,
  char const* response
)
{
  int data_object = 0;
  size_t n;
  cJSON * json = NULL;
  cJSON * result = NULL;
  cJSON * message = NULL;
  cJSON * id = NULL;

  int X = 1234;

  if (cryptolens_check_error(e)) { goto end; }

  json = cJSON_Parse(response);
  if (json == NULL) { cryptolens_set_error(e, 2, 1, 0); goto end; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, 2, X, 0); goto end; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      // TODO: Set unknown server reply
      cryptolens_set_error(e, 2, 1, 0);
      goto end;
    }
    // TODO: parser message
    cryptolens_set_error(e, 2, 1, 0);
    goto end;
  }

  id = cJSON_GetObjectItemCaseSensitive(json, "id");
  if (id == NULL || !cJSON_IsNumber(id)) { cryptolens_set_error(e, 2, X, 0); goto end; }

  data_object = id->valueint;

end:
  cJSON_Delete(json);

  return data_object;
}

void
cryptolens_RP_parse_DO_additive(
  cryptolens_error_t * e,
  void * o,
  char const* response
)
{
  size_t n;
  cJSON * json = NULL;
  cJSON * result = NULL;
  cJSON * message = NULL;

  int X = 1234;

  if (cryptolens_check_error(e)) { goto end; }

  json = cJSON_Parse(response);
  if (json == NULL) { cryptolens_set_error(e, 2, 1, 0); goto end; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, 2, X, 0); goto end; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      // TODO: Set unknown server reply
      cryptolens_set_error(e, 2, 1, 0);
      goto end;
    }
    // TODO: parser message
    cryptolens_set_error(e, 2, 1, 0);
    goto end;
  }

end:
  cJSON_Delete(json);
}

void
cryptolens_RP_parse_license_key(
  cryptolens_error_t * e,
  void * o,
  char const* licenseKey
)
{
#if 0
  size_t n;
  cJSON * json = NULL;
  cJSON * result = NULL;
  cJSON * message = NULL;
  cJSON * licenseKey = NULL;
  cJSON * signature = NULL;

  int X = 1234;

  *licenseKeyBase64 = NULL;
  *signatureBase64 = NULL;

  if (cryptolens_check_error(e)) { goto end; }

  json = cJSON_Parse(response);
  if (json == NULL) { cryptolens_set_error(e, 2, 1, 0); goto end; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, 2, X, 0); goto end; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      // TODO: Set unknown server reply
      goto end;
    }
    // TODO: parser message
    goto end;
  }

  licenseKey = cJSON_GetObjectItemCaseSensitive(json, "licenseKey");
  if (licenseKey == NULL) { cryptolens_set_error(e, 2, X, 0); goto end; }

  signature = cJSON_GetObjectItemCaseSensitive(json, "signature");
  if (signature == NULL) { cryptolens_set_error(e, 2, X, 0); goto end; }

  if (!cJSON_IsString(licenseKey) || !cJSON_IsString(signature)) {
    cryptolens_set_error(e, 2, X, 0);
    goto end;
  }

  n = strlen(licenseKey->valuestring);
  *licenseKeyBase64 = malloc(n + 1);
  if (*licenseKeyBase64 == NULL) { cryptolens_set_error(e, 2, X, 0); goto end; }
  strlcpy(*licenseKeyBase64, licenseKey->valuestring, n+1);

  n = strlen(signature->valuestring);
  *signatureBase64 = malloc(n + 1);
  if (*signatureBase64 == NULL) { cryptolens_set_error(e, 2, X, 0); goto end; }
  strlcpy(*signatureBase64, signature->valuestring, n+1);

end:
  cJSON_Delete(json);

  if (cryptolens_check_error(e)) {
    free(*licenseKeyBase64);
    free(*signatureBase64);

    *licenseKeyBase64 = NULL;
    *signatureBase64 = NULL;
  }
#endif
}
