#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "cJSON.h"

#include "cryptolens.h"


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

  if (cryptolens_check_error(e)) { goto error; }

  *licenseKeyBase64 = NULL;
  *signatureBase64 = NULL;

  json = cJSON_Parse(response);
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 1, 0); goto error; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 2, 0); goto error; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      cryptolens_set_error(e, CRYPTOLENS_ES_RP, 3, 0);
      goto error;
    }
    // TODO Parse message and set reason correctly
    cryptolens_set_error(e, CRYPTOLENS_ES_RP, 4 0);
    goto error;
  }

  licenseKey = cJSON_GetObjectItemCaseSensitive(json, "licenseKey");
  if (licenseKey == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 5, 0); goto error; }

  signature = cJSON_GetObjectItemCaseSensitive(json, "signature");
  if (signature == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 6, 0); goto error; }

  if (!cJSON_IsString(licenseKey) || !cJSON_IsString(signature)) {
    cryptolens_set_error(e, CRYPTOLENS_ES_RP, 7, 0);
    goto error;
  }

  n = strlen(licenseKey->valuestring);
  *licenseKeyBase64 = malloc(n + 1);
  if (*licenseKeyBase64 == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 8, 0); goto error; }
  strlcpy(*licenseKeyBase64, licenseKey->valuestring, n+1);

  n = strlen(signature->valuestring);
  *signatureBase64 = malloc(n + 1);
  if (*signatureBase64 == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 9, 0); goto error; }
  strlcpy(*signatureBase64, signature->valuestring, n+1);

  goto end;

error:
    free(*licenseKeyBase64);
    free(*signatureBase64);

    *licenseKeyBase64 = NULL;
    *signatureBase64 = NULL;

end:
  cJSON_Delete(json);
}

cryptolens_DOL_entry_t *
cryptolens_RP_parse_DO_list(
  cryptolens_error_t * e,
  void * o,
  char const* response
)
{
  size_t n = 0;
  size_t m = 0;
  cJSON * json = NULL;
  cJSON * result = NULL;
  cJSON * message = NULL;
  cJSON * data_objects = NULL;
  cJSON * child = NULL;

  cJSON * field = NULL;
  cryptolens_DOL_entry_t * l = NULL;
  cryptolens_DOL_entry_t * l_ret = NULL;

  int X = 1239;

  if (cryptolens_check_error(e)) { goto error; }

  json = cJSON_Parse(response);
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 10, 0); goto error; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 11, 0); goto error; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      // TODO: Set unknown server reply
      cryptolens_set_error(e, CRYPTOLENS_ES_RP, 12, 0);
      goto error;
    }
    // TODO: parser message
    cryptolens_set_error(e, CRYPTOLENS_ES_RP, 13, 0);
    goto error;
  }

  data_objects = cJSON_GetObjectItemCaseSensitive(json, "dataObjects");
  if (data_objects == NULL || !cJSON_IsArray(data_objects)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 14, 0); goto error; }

  n = cJSON_GetArraySize(data_objects);
  if (n == 0) { goto error; }

  l = (cryptolens_DOL_entry_t *)calloc(n, sizeof(cryptolens_DOL_entry_t));
  if (!l) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, CRYPTOLENS_ER_ALLOC_FAILED, 0); goto error; }

  l_ret = l;
  // TODO: error check

  child = data_objects->child;
  while (child != NULL) {
    l->prev = child->prev == NULL ? NULL : l-1;
    l->next = child->next == NULL ? NULL : l+1;

    field = cJSON_GetObjectItemCaseSensitive(child, "id");
    if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 15, 0); goto error; }
    l->data_object.id = field->valueint;

    field = cJSON_GetObjectItemCaseSensitive(child, "name");
    if (field == NULL || !cJSON_IsString(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 16, 0); goto error; }
    m = strlen(field->valuestring);
    l->data_object.name = malloc(m+1);
    if (!l->data_object.name) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 17, 0); goto error; }
    strlcpy(l->data_object.name, field->valuestring, m+1);

    field = cJSON_GetObjectItemCaseSensitive(child, "intValue");
    if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 18, 0); goto error; }
    l->data_object.int_value = field->valueint;

    field = cJSON_GetObjectItemCaseSensitive(child, "stringValue");
    if (field == NULL || !cJSON_IsString(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 19, 0); goto error; }
    m = strlen(field->valuestring);
    l->data_object.string_value = malloc(m+1);
    if (!l->data_object.string_value) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 20, 0); goto error; }
    strlcpy(l->data_object.string_value, field->valuestring, m+1);

    field = cJSON_GetObjectItemCaseSensitive(child, "referencerType");
    l->referencer_type = cJSON_IsNumber(field) ? field->valueint : -1;

    field = cJSON_GetObjectItemCaseSensitive(child, "referencerId");
    l->referencer_id = cJSON_IsNumber(field) ? field->valueint : -1;

    child = child->next;
    l += 1;
  }

  goto end;

error:
  // TODO: traverse l_ret and free any strings
  free(l_ret);

end:
  cJSON_Delete(json);

  return l_ret;
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

  if (cryptolens_check_error(e)) { goto error; }

  json = cJSON_Parse(response);
  if (!json) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 21, 0); goto error; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (!result || !cJSON_IsNumber(result)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 22, 0); goto error; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      // TODO: Set unknown server reply
      cryptolens_set_error(e, CRYPTOLENS_ES_RP, 23, 0);
      goto error;
    }
    // TODO: parser message
    cryptolens_set_error(e, CRYPTOLENS_ES_RP, 23, 0);
    goto error;
  }

  id = cJSON_GetObjectItemCaseSensitive(json, "id");
  if (!id || !cJSON_IsNumber(id)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 24, 0); goto error; }

  data_object = id->valueint;

  goto end;

error:
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

  if (cryptolens_check_error(e)) { goto error; }

  json = cJSON_Parse(response);
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 25, 0); goto error; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 26, 0); goto error; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      // TODO: Set unknown server reply
      cryptolens_set_error(e, CRYPTOLENS_ES_RP, 27, 0);
      goto error;
    }
    // TODO: parser message
    cryptolens_set_error(e, CRYPTOLENS_ES_RP, 28, 0);
    goto error;
  }

  goto end;

error:
end:
  cJSON_Delete(json);
}

static
void
LK_set_feature(
  cryptolens_error_t * e,
  cJSON * json,
  int * feature,
  char const*  feature_name
)
{
  cJSON * f = NULL;

  f = cJSON_GetObjectItemCaseSensitive(json, feature_name);
  if (f == NULL || !cJSON_IsBool(f)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 29, 0); goto error; }

  *feature = f->valueint;

  goto end;

error:
end:
  return;
}

cryptolens_LK_t *
cryptolens_RP_parse_license_key(
  cryptolens_error_t * e,
  void * o,
  char const* license_key_string
)
{
  cryptolens_LK_t * license_key = NULL;
  cJSON * json = NULL;
  cJSON * field = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  json = cJSON_Parse(license_key_string);
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 30, 0); goto error; }

  license_key = (cryptolens_LK_t *)malloc(sizeof(cryptolens_LK_t));
  if (license_key == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 31, 0); goto error; }

  field = cJSON_GetObjectItemCaseSensitive(json, "Expires");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 32, 0); goto error; }
  license_key->expires = field->valuedouble;

  LK_set_feature(e, json, &(license_key->f1), "F1");
  LK_set_feature(e, json, &(license_key->f2), "F2");
  LK_set_feature(e, json, &(license_key->f3), "F3");
  LK_set_feature(e, json, &(license_key->f4), "F4");
  LK_set_feature(e, json, &(license_key->f5), "F5");
  LK_set_feature(e, json, &(license_key->f6), "F6");
  LK_set_feature(e, json, &(license_key->f7), "F7");
  LK_set_feature(e, json, &(license_key->f8), "F8");

  field = cJSON_GetObjectItemCaseSensitive(json, "ProductId");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 33, 0); goto error; }
  license_key->product_id = field->valueint;

  field = cJSON_GetObjectItemCaseSensitive(json, "Created");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 34, 0); goto error; }
  license_key->created = field->valuedouble;

  field = cJSON_GetObjectItemCaseSensitive(json, "Period");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 35, 0); goto error; }
  license_key->period = field->valueint;

  field = cJSON_GetObjectItemCaseSensitive(json, "Block");
  if (field == NULL || !cJSON_IsBool(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 36, 0); goto error; }
  license_key->block = field->valueint;

  field = cJSON_GetObjectItemCaseSensitive(json, "TrialActivation");
  if (field == NULL || !cJSON_IsBool(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 37, 0); goto error; }
  license_key->trial_activation = field->valueint;

  field = cJSON_GetObjectItemCaseSensitive(json, "SignDate");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 38, 0); goto error; }
  license_key->sign_date = field->valuedouble;

  goto end;

error:
  // TODO: When we add more fields to license_key we need to free any initialized ones
  free(license_key);
  license_key = NULL;

end:
  cJSON_Delete(json);

  return license_key;
}
