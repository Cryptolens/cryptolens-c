#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cJSON.h"

#include "cryptolens/internal/decode_base64.h"
#include "cryptolens/cryptolens.h"

#ifndef CRYPTOLENS_ACTIVATE_MODEL_VERSION
#define CRYPTOLENS_ACTIVATE_MODEL_VERSION "3"
#endif

#ifndef CRYPTOLENS_ACTIVATE_FLOATING_MODEL_VERSION
#define CRYPTOLENS_ACTIVATE_FLOATING_MODEL_VERSION "3"
#endif

cryptolens_t *
cryptolens_init(
  cryptolens_error_t * e
)
{
  cryptolens_t * o = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  o = malloc(sizeof(cryptolens_t));
  if (o == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_ALLOC_FAILED, 0); goto error; }

  o->rh = cryptolens_RH_new(e);
  if (cryptolens_check_error(e)) { goto error; }

  o->signature_verifier = cryptolens_SV_init(e);
  if (cryptolens_check_error(e)) { goto error; }

  goto end;

error:
  if (o) {
    cryptolens_RH_destroy(o->rh);
    cryptolens_SV_destroy(o->signature_verifier);
  }

  free(o);

end:
  return o;
}

void
cryptolens_destroy(
  cryptolens_t * o
)
{
  if (o == NULL) { return; }

  cryptolens_RH_destroy(o->rh);
  cryptolens_SV_destroy(o->signature_verifier);
  free(o);
}

void
cryptolens_LK_destroy(
  cryptolens_LK_t * license_key
)
{
  if (license_key == NULL) { return; }

#ifndef CRYPTOLENS_DISABLE_RESELLER
  if (license_key->reseller) {
    free(license_key->reseller->name);
    free(license_key->reseller->url);
    free(license_key->reseller->email);
    free(license_key->reseller->phone);
    free(license_key->reseller->description);
  }
  free(license_key->reseller);
#endif

  cryptolens_DOL_destroy(license_key->data_objects);

  free(license_key);
}

void
cryptolens_set_modulus_base64(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* modulus_base64
)
{
  if (!o) { return; }

  cryptolens_SV_set_modulus_base64(e, o->signature_verifier, modulus_base64);
}

void
cryptolens_set_exponent_base64(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* exponent_base64
)
{
  if (!o) { return; }

  cryptolens_SV_set_exponent_base64(e, o->signature_verifier, exponent_base64);
}

cryptolens_LK_t *
cryptolens_handle_activate_response(
  cryptolens_error_t * e,
  cryptolens_signature_verifier_t * signature_verifier,
  char const* response
)
{
  char * license_key_base64 = NULL;
  char * signature_base64 = NULL;

  unsigned char * license_key = NULL;
  size_t license_key_len = 0;
  unsigned char * signature = NULL;
  size_t signature_len = 0;

  cryptolens_LK_t * lk = NULL;

  int valid = 0;

  if (cryptolens_check_error(e)) { goto end; }

  cryptolens_RP_parse_activate_response(e, NULL, response, &license_key_base64, &signature_base64);

  cryptolens_IN_decode_base64(e, license_key_base64, &license_key, &license_key_len);
  cryptolens_IN_decode_base64(e, signature_base64, &signature, &signature_len);

  valid = cryptolens_SV_verify(e, signature_verifier, license_key, license_key_len, signature, signature_len);
  if (!valid) { cryptolens_weak_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_INVALID_SIGNATURE, 0); goto error; }

  lk = cryptolens_RP_parse_license_key(e, NULL, license_key);

  goto end;

error:
end:
  free(license_key);
  free(signature);
  free(license_key_base64);
  free(signature_base64);

  return lk;
}

cryptolens_LK_t *
cryptolens_handle_activate_floating_response(
  cryptolens_error_t * e,
  cryptolens_signature_verifier_t * signature_verifier,
  char const* response,
  char const* floating_interval
)
{
  char * license_key_base64 = NULL;
  char * signature_base64 = NULL;

  unsigned char * license_key = NULL;
  size_t license_key_len = 0;
  unsigned char * signature = NULL;
  size_t signature_len = 0;

  cryptolens_LK_t * lk = NULL;

  int valid = 0;

  if (cryptolens_check_error(e)) { goto end; }

  cryptolens_RP_parse_activate_floating_response(e, NULL, response, &license_key_base64, &signature_base64, floating_interval);

  cryptolens_IN_decode_base64(e, license_key_base64, &license_key, &license_key_len);
  cryptolens_IN_decode_base64(e, signature_base64, &signature, &signature_len);

  valid = cryptolens_SV_verify(e, signature_verifier, license_key, license_key_len, signature, signature_len);
  if (!valid) { cryptolens_weak_set_error(e, CRYPTOLENS_ES_MAIN, CRYPTOLENS_ER_INVALID_SIGNATURE, 0); goto error; }

  lk = cryptolens_RP_parse_license_key(e, NULL, license_key);

  goto end;

error:
end:
  free(license_key);
  free(signature);
  free(license_key_base64);
  free(signature_base64);

  return lk;
}

cryptolens_LK_t *
cryptolens_activate(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,
  char const* product_id,
  char const* key,
  char const* machine_code
)
{
  return cryptolens_IN_activate(e, o->rh, o->signature_verifier, token, product_id, key, machine_code);
}

cryptolens_LK_t *
cryptolens_activate_floating(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,
  char const* product_id,
  char const* key,
  char const* floating_interval,
  char const* machine_code
)
{
  return cryptolens_IN_activate_floating(e, o->rh, o->signature_verifier, token, product_id, key, floating_interval, machine_code);
}


void
cryptolens_deactivate(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,
  char const* product_id,
  char const* key,
  char const* machine_code
)
{
  cryptolens_IN_deactivate(e, o->rh, token, product_id, key, machine_code);
}

void
cryptolens_deactivate_floating(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,
  char const* product_id,
  char const* key,
  char const* machine_code
)
{
  cryptolens_IN_deactivate_floating(e, o->rh, token, product_id, key, machine_code);
}

void
cryptolens_IN_deactivate(
  cryptolens_error_t * e,
  cryptolens_RH_t * rh,
  char const* token,
  char const* product_id,
  char const* key,
  char const* machine_code
)
{
  cryptolens_RHP_builder_t* r = NULL;
  char * response = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  r = cryptolens_RHP_new(e, rh, "api/key/Deactivate");

  if (machine_code == NULL) { machine_code = cryptolens_MC_get_machine_code(e); }

  cryptolens_RHP_add_argument(e, r, "token", token);
  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "MachineCode", machine_code);
  cryptolens_RHP_add_argument(e, r, "v", "1");

  response = cryptolens_RHP_perform(e, r);

  cryptolens_RP_parse_deactivate_response(e, NULL, response);

  goto end;

error:
end:
  free(response);
  cryptolens_RHP_destroy(r);
}

void
cryptolens_IN_deactivate_floating(
  cryptolens_error_t * e,
  cryptolens_RH_t * rh,
  char const* token,
  char const* product_id,
  char const* key,
  char const* machine_code
)
{
  cryptolens_RHP_builder_t* r = NULL;
  char * response = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  r = cryptolens_RHP_new(e, rh, "api/key/Deactivate");

  if (machine_code == NULL) { machine_code = cryptolens_MC_get_machine_code(e); }

  cryptolens_RHP_add_argument(e, r, "token", token);
  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "MachineCode", machine_code);
  cryptolens_RHP_add_argument(e, r, "Floating", "true");
  cryptolens_RHP_add_argument(e, r, "v", "1");

  response = cryptolens_RHP_perform(e, r);

  cryptolens_RP_parse_deactivate_floating_response(e, NULL, response);

  goto end;

error:
end:
  free(response);
  cryptolens_RHP_destroy(r);
}


cryptolens_LK_t *
cryptolens_IN_activate(
  cryptolens_error_t * e,
  cryptolens_RH_t * rh,
  cryptolens_signature_verifier_t * signature_verifier,
  char const* token,
  char const* product_id,
  char const* key,
  char const* machine_code
)
{
  cryptolens_LK_t * license_key = NULL;
  cryptolens_RHP_builder_t * r = NULL;
  char * response = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  r = cryptolens_RHP_new(e, rh, "api/key/Activate");

  if (machine_code == NULL) { machine_code = cryptolens_MC_get_machine_code(e); }

  cryptolens_RHP_add_argument(e, r, "token", token);
  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "Sign", "true");
  cryptolens_RHP_add_argument(e, r, "MachineCode", machine_code);
//  add_argument(e, r, "FieldsToReturn", "0");
  cryptolens_RHP_add_argument(e, r, "ModelVersion", CRYPTOLENS_ACTIVATE_MODEL_VERSION);
  cryptolens_RHP_add_argument(e, r, "SignMethod", "1");
  cryptolens_RHP_add_argument(e, r, "v", "1");

  response = cryptolens_RHP_perform(e, r);

  license_key = cryptolens_handle_activate_response(e, signature_verifier, response);

  goto end;

error:
end:
  free(response);
  cryptolens_RHP_destroy(r);

  return license_key;
}

cryptolens_LK_t *
cryptolens_IN_activate_floating(
  cryptolens_error_t * e,
  cryptolens_RH_t * rh,
  cryptolens_signature_verifier_t * signature_verifier,
  char const* token,
  char const* product_id,
  char const* key,
  char const* floating_interval,
  char const* machine_code
)
{
  cryptolens_LK_t * license_key = NULL;
  cryptolens_RHP_builder_t * r = NULL;
  char * response = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  r = cryptolens_RHP_new(e, rh, "api/key/Activate");

  if (machine_code == NULL) { machine_code = cryptolens_MC_get_machine_code(e); }


  cryptolens_RHP_add_argument(e, r, "token", token);
  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "Sign", "true");
  cryptolens_RHP_add_argument(e, r, "MachineCode", machine_code);
//  add_argument(e, r, "FieldsToReturn", "0");
  cryptolens_RHP_add_argument(e, r, "ModelVersion", CRYPTOLENS_ACTIVATE_FLOATING_MODEL_VERSION);
  cryptolens_RHP_add_argument(e, r, "SignMethod", "1");
  cryptolens_RHP_add_argument(e, r, "FloatingTimeInterval", floating_interval);
  cryptolens_RHP_add_argument(e, r, "v", "1");

  response = cryptolens_RHP_perform(e, r);

  license_key = cryptolens_handle_activate_floating_response(e, signature_verifier, response, floating_interval);

  goto end;

error:
end:
  free(response);
  cryptolens_RHP_destroy(r);

  return license_key;
}

int
cryptolens_LK_has_feature_template(cryptolens_LK_t * license_key, char const* key)
{

  char const* json_string = NULL;

  if (license_key == NULL) { return 0; }
  json_string = license_key->notes;
  if (json_string == NULL) { return 0; }

  cJSON * json = cJSON_Parse(json_string);
  if (json == NULL) { return 0; }
  if (!cJSON_IsArray(json)) { return 0; }

  cJSON * w;
  cJSON * v = json;
  char const* p = key;
  char const* q = key;
  while (1) {
    while (*q != '.' && *q != '\0') { ++q; }

    w = NULL;
    cJSON * u;
    cJSON_ArrayForEach(u, v) {
      char const* c1 = p;
      char const* c2 = NULL;
      if (cJSON_IsString(u)) {
        c2 = u->valuestring;
      } else if (cJSON_IsArray(u) && cJSON_GetArraySize(u) > 0) {
        cJSON * e = cJSON_GetArrayItem(u, 0);
        if (cJSON_IsString(e)) { c2 = e->valuestring; }
      }

      if (c2 == NULL) { continue; }

      while (c1 < q && *c2 != '\0') {
        if (*c1 != *c2) { break; }
        c1++; c2++;
      }

      if (c1 == q && *c2 == '\0') { w = u; break; }
    }

    if (w == NULL) { return 0; }

    v = w;

    if (*q == '\0') { return 1; }
    else            { p = q = q+1; }
  }

  return 0;
}
