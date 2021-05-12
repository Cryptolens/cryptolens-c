#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "cJSON.h"

#include "cryptolens/cryptolens.h"


size_t
strlcpy(char *dst, const char *src, size_t dsize);

static
int
activate_parse_server_error_message(char const* server_response)
{
  if (server_response == NULL) { return CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY; }

  if (0 == strcmp(server_response, "Unable to authenticate.")) {
    return CRYPTOLENS_ER_INVALID_ACCESS_TOKEN;
  }

  if (0 == strcmp(server_response, "Access denied.")) {
    return CRYPTOLENS_ER_ACCESS_DENIED;
  }

  if (0 == strcmp(server_response, "The input parameters were incorrect.")) {
    return CRYPTOLENS_ER_INCORRECT_INPUT_PARAMETER;
  }

  if (0 == strcmp(server_response, "Could not find the product.")) {
    return CRYPTOLENS_ER_PRODUCT_NOT_FOUND;
  }

  if (0 == strcmp(server_response, "Could not find the key.")) {
    return CRYPTOLENS_ER_KEY_NOT_FOUND;
  }

  if (0 == strcmp(server_response, "The key is blocked and cannot be accessed.")) {
    return CRYPTOLENS_ER_KEY_BLOCKED;
  }

  if (0 == strcmp(server_response, "Cannot activate the new device as the limit has been reached.")) {
    return CRYPTOLENS_ER_DEVICE_LIMIT_REACHED;
  }

  return CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY;
}

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
      cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY, 0);
      goto error;
    }

    int reason = activate_parse_server_error_message(message->valuestring);
    cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, reason, 0);
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

void
cryptolens_RP_parse_activate_floating_response(
  cryptolens_error_t * e,
  void * o,
  char const* response,
  char ** licenseKeyBase64,
  char ** signatureBase64,
  char const* floating_interval
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
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 41, 0); goto error; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 42, 0); goto error; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY, 0);
      goto error;
    }

    int reason = activate_parse_server_error_message(message->valuestring);
    cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, reason, 0);
    goto error;
  }

  licenseKey = cJSON_GetObjectItemCaseSensitive(json, "licenseKey");
  if (licenseKey == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 45, 0); goto error; }

  signature = cJSON_GetObjectItemCaseSensitive(json, "signature");
  if (signature == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 46, 0); goto error; }

  if (!cJSON_IsString(licenseKey) || !cJSON_IsString(signature)) {
    cryptolens_set_error(e, CRYPTOLENS_ES_RP, 47, 0);
    goto error;
  }

  n = strlen(licenseKey->valuestring);
  *licenseKeyBase64 = malloc(n + 1);
  if (*licenseKeyBase64 == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 48, 0); goto error; }
  strlcpy(*licenseKeyBase64, licenseKey->valuestring, n+1);

  n = strlen(signature->valuestring);
  *signatureBase64 = malloc(n + 1);
  if (*signatureBase64 == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 49, 0); goto error; }
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

void
cryptolens_RP_parse_deactivate_response(
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
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 39, 0); goto error; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 40, 0); goto error; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY, 0);
      goto error;
    }

    int reason = activate_parse_server_error_message(message->valuestring);
    cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, reason, 0);
    goto error;
  }

  goto end;

error:
end:
  cJSON_Delete(json);
}

void
cryptolens_RP_parse_deactivate_floating_response(
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
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 39, 0); goto error; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 40, 0); goto error; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY, 0);
      goto error;
    }

    int reason = activate_parse_server_error_message(message->valuestring);
    cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, reason, 0);
    goto error;
  }

  goto end;

error:
end:
  cJSON_Delete(json);
}

static
cryptolens_DOL_entry_t *
parse_DO_list(
  cryptolens_error_t * e,
  cJSON * data_objects
)
{
  size_t n = 0;
  size_t m = 0;
  cryptolens_DOL_entry_t * l = NULL;
  cryptolens_DOL_entry_t * l_ret = NULL;

  cJSON * child = NULL;
  cJSON * field = NULL;

  if (cryptolens_check_error(e)) { goto error; }
  if (!data_objects) { goto end; }

  n = cJSON_GetArraySize(data_objects);
  if (n == 0) { goto error; }

  l = (cryptolens_DOL_entry_t *)calloc(n, sizeof(cryptolens_DOL_entry_t));
  if (!l) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, CRYPTOLENS_ER_ALLOC_FAILED, 0); goto error; }

  l_ret = l;

  child = data_objects->child;
  while (child != NULL) {
    l->prev = child->prev == NULL ? NULL : l-1;
    l->next = child->next == NULL ? NULL : l+1;

    field = cJSON_GetObjectItem(child, "id");
    if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 15, 0); goto error; }
    l->data_object.id = field->valueint;

    field = cJSON_GetObjectItem(child, "name");
    if (field == NULL || !cJSON_IsString(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 16, 0); goto error; }
    m = strlen(field->valuestring);
    l->data_object.name = malloc(m+1);
    if (!l->data_object.name) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 17, 0); goto error; }
    strlcpy(l->data_object.name, field->valuestring, m+1);

    field = cJSON_GetObjectItem(child, "intValue");
    if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 18, 0); goto error; }
    l->data_object.int_value = field->valueint;

    field = cJSON_GetObjectItem(child, "stringValue");
    if (field == NULL || !cJSON_IsString(field)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 19, 0); goto error; }
    m = strlen(field->valuestring);
    l->data_object.string_value = malloc(m+1);
    if (!l->data_object.string_value) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 20, 0); goto error; }
    strlcpy(l->data_object.string_value, field->valuestring, m+1);

    field = cJSON_GetObjectItem(child, "referencerType");
    l->referencer_type = cJSON_IsNumber(field) ? field->valueint : -1;

    field = cJSON_GetObjectItem(child, "referencerId");
    l->referencer_id = cJSON_IsNumber(field) ? field->valueint : -1;

    child = child->next;
    l += 1;
  }

  goto end;

error:
  if (l_ret) {
    l = l_ret;
    while (l->next) {
      free(l->data_object.name);
      free(l->data_object.string_value);
    }
    free(l_ret);
    l_ret = NULL;
  }

end:
  return l_ret;
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

  cryptolens_DOL_entry_t * list = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  json = cJSON_Parse(response);
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 10, 0); goto error; }

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if (result == NULL || !cJSON_IsNumber(result)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 11, 0); goto error; }

  if (result->valueint != 0) {
    message = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message == NULL || !cJSON_IsString(message)) {
      cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY, 0);
      goto error;
    }

    int reason = activate_parse_server_error_message(message->valuestring);
    cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, reason, 0);
    goto error;
  }

  data_objects = cJSON_GetObjectItemCaseSensitive(json, "dataObjects");
  if (data_objects == NULL || !cJSON_IsArray(data_objects)) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 14, 0); goto error; }

  list = parse_DO_list(e, data_objects);

  goto end;

error:
end:
  cJSON_Delete(json);

  return list;
}

// TODO: Should return the newly created data object?
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
      cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY, 0);
      goto error;
    }

    int reason = activate_parse_server_error_message(message->valuestring);
    cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, reason, 0);
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
      cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY, 0);
      goto error;
    }

    int reason = activate_parse_server_error_message(message->valuestring);
    cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, reason, 0);
    goto error;
  }

  goto end;

error:
end:
  cJSON_Delete(json);
}

#ifndef CRYPTOLENS_DISABLE_RESELLER
static
cryptolens_RS_t *
parse_RS(
  cryptolens_error_t * e,
  cJSON * json
)
{
  cryptolens_RS_t * reseller = NULL;
  cJSON * field = NULL;
  size_t m = 0;

  if (cryptolens_check_error(e)) { goto end; }

  if (!cJSON_IsObject(json)) { goto end; }

  reseller = malloc(sizeof(cryptolens_RS_t));
  if (!reseller) { cryptolens_set_error(e, 123, 3, 0); goto error; }

  reseller->id = 0;
  reseller->invite_id = 0;
  reseller->reseller_user_id = 0;
  reseller->created = 0;
  reseller->name = NULL;
  reseller->url = NULL;
  reseller->email = NULL;
  reseller->phone = NULL;
  reseller->description = NULL;

  field = cJSON_GetObjectItem(json, "Id");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 123, 4, 0); goto error; }
  reseller->id = field->valueint;

  field = cJSON_GetObjectItem(json, "InviteId");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 123, 4, 0); goto error; }
  reseller->id = field->valueint;

  field = cJSON_GetObjectItem(json, "ResellerUserId");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 123, 4, 0); goto error; }
  reseller->id = field->valueint;

  field = cJSON_GetObjectItem(json, "Created");
  if (field == NULL || !cJSON_IsNumber(field)) { cryptolens_set_error(e, 123, 11, 0); goto error; }
  reseller->created = field->valuedouble;

  field = cJSON_GetObjectItem(json, "Name");
  if (field == NULL || !cJSON_IsString(field)) { reseller->name = calloc(1, 1); }
  else {
    m = strlen(field->valuestring);
    reseller->name = malloc(m+1);
    if (!reseller->name) { cryptolens_set_error(e, 123, 6, 0); goto error; }
    strlcpy(reseller->name, field->valuestring, m+1);
  }

  field = cJSON_GetObjectItem(json, "Url");
  if (field == NULL || !cJSON_IsString(field)) { reseller->url = calloc(1, 1); }
  else {
    m = strlen(field->valuestring);
    reseller->url = malloc(m+1);
    if (!reseller->url) { cryptolens_set_error(e, 123, 8, 0); goto error; }
    strlcpy(reseller->url, field->valuestring, m+1);
  }

  field = cJSON_GetObjectItem(json, "Email");
  if (field == NULL || !cJSON_IsString(field)) { reseller->email = calloc(1, 1); }
  else {
    m = strlen(field->valuestring);
    reseller->email = malloc(m+1);
    if (!reseller->email) { cryptolens_set_error(e, 123, 8, 0); goto error; }
    strlcpy(reseller->email, field->valuestring, m+1);
  }

  field = cJSON_GetObjectItem(json, "Phone");
  if (field == NULL || !cJSON_IsString(field)) { reseller->phone = calloc(1, 1); }
  else {
    m = strlen(field->valuestring);
    reseller->phone = malloc(m+1);
    if (!reseller->phone) { cryptolens_set_error(e, 123, 8, 0); goto error; }
    strlcpy(reseller->phone, field->valuestring, m+1);
  }

  field = cJSON_GetObjectItem(json, "Description");
  if (field == NULL || !cJSON_IsString(field)) { reseller->description = calloc(1, 1); }
  else {
    m = strlen(field->valuestring);
   reseller->description = malloc(m+1);
    if (!reseller->description) { cryptolens_set_error(e, 123, 10, 0); goto error; }
    strlcpy(reseller->description, field->valuestring, m+1);
  }

  goto end;

error:
  if (reseller) {
    free(reseller->name);
    free(reseller->url);
    free(reseller->email);
    free(reseller->phone);
    free(reseller->description);
  }

  free(reseller);
  reseller = NULL;

end:
  return reseller;
}
#endif

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
  size_t n = 0;

  if (cryptolens_check_error(e)) { goto error; }

  json = cJSON_Parse(license_key_string);
  if (json == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 30, 0); goto error; }

  license_key = (cryptolens_LK_t *)malloc(sizeof(cryptolens_LK_t));
  if (license_key == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 31, 0); goto error; }

#ifndef CRYPTOLENS_DISABLE_RESELLER
  license_key->key = NULL;
  license_key->notes = NULL;
  license_key->customer = NULL;
  license_key->activated_machines = NULL;
  license_key->allowed_machines = NULL;
  license_key->data_objects = NULL;
  license_key->reseller = NULL;
#endif

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

  field = cJSON_GetObjectItemCaseSensitive(json, "Notes");
  if (field != NULL && cJSON_IsString(field)) {
    n = strlen(field->valuestring);
    license_key->notes = malloc(n+1);
    if (license_key->notes == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RP, 44, 0); goto error; }
    strlcpy(license_key->notes, field->valuestring, n+1);
  }

  field = cJSON_GetObjectItemCaseSensitive(json, "DataObjects");
  license_key->data_objects = parse_DO_list(e, field);
  if(cryptolens_check_error(e)) { goto error; }

#ifndef CRYPTOLENS_DISABLE_RESELLER
  field = cJSON_GetObjectItem(json, "Reseller");
  license_key->reseller = parse_RS(e, field);
  if(cryptolens_check_error(e)) { goto error; }
#endif

  goto end;

error:
  cryptolens_LK_destroy(license_key);
  license_key = NULL;

end:
  cJSON_Delete(json);

  return license_key;
}
