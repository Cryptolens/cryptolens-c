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

  data_objects = cJSON_GetObjectItemCaseSensitive(json, "dataObjects");
  if (data_objects == NULL || !cJSON_IsArray(data_objects)) { cryptolens_set_error(e, 2, 1240, 0); goto end; }

  n = cJSON_GetArraySize(data_objects);
  if (n == 0) { goto end; }

  l = malloc(sizeof(cryptolens_DOL_entry_t)*n); // TODO: calloc?
  l_ret = l;
  // TODO: error check

  child = data_objects->child;
  while (child != NULL) {
    l->prev = child->prev == NULL ? NULL : l-1;
    l->next = child->next == NULL ? NULL : l+1;

    field = cJSON_GetObjectItemCaseSensitive(child, "id");
    if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 2, 1241, 0); goto end; }
    l->data_object.id = field->valueint;

    field = cJSON_GetObjectItemCaseSensitive(child, "name");
    if (field == NULL || !cJSON_IsString(field)) { cryptolens_set_error(e, 2, 1242, 0); goto end; }
    m = strlen(field->valuestring);
    l->data_object.name = malloc(m+1);
    // TODO: Error check
    strlcpy(l->data_object.name, field->valuestring, m+1);

    field = cJSON_GetObjectItemCaseSensitive(child, "intValue");
    if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 2, 1243, 0); goto end; }
    l->data_object.int_value = field->valueint;

    field = cJSON_GetObjectItemCaseSensitive(child, "stringValue");
    if (field == NULL || !cJSON_IsString(field)) { cryptolens_set_error(e, 2, 1244, 0); goto end; }
    m = strlen(field->valuestring);
    l->data_object.string_value = malloc(m+1);
    // TODO: Error check
    strlcpy(l->data_object.string_value, field->valuestring, m+1);

    field = cJSON_GetObjectItemCaseSensitive(child, "referencerType");
    l->referencer_type = cJSON_IsNumber(field) ? field->valueint : -1;

    field = cJSON_GetObjectItemCaseSensitive(child, "referencerId");
    l->referencer_id = cJSON_IsNumber(field) ? field->valueint : -1;

    child = child->next;
    l += 1;
  }


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
  if (f == NULL || !cJSON_IsBool(f)) { cryptolens_set_error(e, 2, 4398, 0); goto end; }

  *feature = f->valueint;

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

  json = cJSON_Parse(license_key_string);
  if (json == NULL) { cryptolens_set_error(e, 2, 1, 0); goto end; }

  license_key = (cryptolens_LK_t *)malloc(sizeof(cryptolens_LK_t));
  if (license_key == NULL) { cryptolens_set_error(e, 2, 1, 0); goto end; }

  field = cJSON_GetObjectItemCaseSensitive(json, "Expires");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 2, 9420, 0); goto end; }
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
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 2, 9421, 0); goto end; }
  license_key->product_id = field->valueint;

  field = cJSON_GetObjectItemCaseSensitive(json, "Created");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 2, 9422, 0); goto end; }
  license_key->created = field->valuedouble;

  field = cJSON_GetObjectItemCaseSensitive(json, "Period");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 2, 9423, 0); goto end; }
  license_key->period = field->valueint;

  field = cJSON_GetObjectItemCaseSensitive(json, "Block");
  if (field == NULL || !cJSON_IsBool(field)) { cryptolens_set_error(e, 2, 9424, 0); goto end; }
  license_key->block = field->valueint;

  field = cJSON_GetObjectItemCaseSensitive(json, "TrialActivation");
  if (field == NULL || !cJSON_IsBool(field)) { cryptolens_set_error(e, 2, 9425, 0); goto end; }
  license_key->trial_activation = field->valueint;

  field = cJSON_GetObjectItemCaseSensitive(json, "SignDate");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 2, 9426, 0); goto end; }
  license_key->sign_date = field->valuedouble;

end:
  cJSON_Delete(json);

  return license_key;
}
