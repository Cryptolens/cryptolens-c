#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "internal/decode_base64.h"
#include "cryptolens.h"

cryptolens_t *
cryptolens_init(
  cryptolens_error_t * e
)
{
  cryptolens_t * o = malloc(sizeof(cryptolens_t));
  if (o == NULL) { }  // TODO

  o->rh = cryptolens_RH_new(e);
  if (cryptolens_check_error(e)) { } // TODO

  o->signature_verifier = cryptolens_SV_init(e);
  if (cryptolens_check_error(e)) { } // TODO

end:
  return o;
}

void
cryptolens_destroy(
  cryptolens_t * o
)
{
  cryptolens_SV_destroy(o->signature_verifier);
  cryptolens_RH_destroy(o->rh);
  free(o);
}

void
cryptolens_set_modulus_base64(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* modulus_base64
)
{
  cryptolens_SV_set_modulus_base64(e, o->signature_verifier, modulus_base64);
}

void
cryptolens_set_exponent_base64(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* exponent_base64
)
{
  cryptolens_SV_set_exponent_base64(e, o->signature_verifier, exponent_base64);
}

void *
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

  int valid = 0;

  if (cryptolens_check_error(e)) { goto end; }

  cryptolens_RP_parse_activate_response(e, NULL, response, &license_key_base64, &signature_base64);

  cryptolens_IN_decode_base64(e, license_key_base64, &license_key, &license_key_len);
  cryptolens_IN_decode_base64(e, signature_base64, &signature, &signature_len);

  valid = cryptolens_SV_verify(e, signature_verifier, license_key, license_key_len, signature, signature_len);
  if (!valid) { cryptolens_weak_set_error(e, 1234, 2345, 589248); goto end; } // TODO: Update error code

end:
  free(license_key);
  free(signature);
  free(license_key_base64);
  free(signature_base64);

  return NULL;
}

void
cryptolens_activate(
  cryptolens_error_t * e,
  cryptolens_t * o,
  char const* token,
  char const* product_id,
  char const* key
)
{
  cryptolens_IN_activate(e, o->rh, o->signature_verifier, token, product_id, key);
}

void
cryptolens_IN_activate(
  cryptolens_error_t * e,
  cryptolens_RH_t * rh,
  cryptolens_signature_verifier_t * signature_verifier,
  char const* token,
  char const* product_id,
  char const* key
)
{
  cryptolens_RHP_builder_t * r = cryptolens_RHP_new(e, rh, "api/key/Activate");

  char const* machine_code = cryptolens_MC_get_machine_code(e);

  cryptolens_RHP_add_argument(e, r, "token", token);
  cryptolens_RHP_add_argument(e, r, "ProductId", product_id);
  cryptolens_RHP_add_argument(e, r, "Key", key);
  cryptolens_RHP_add_argument(e, r, "Sign", "true");
  cryptolens_RHP_add_argument(e, r, "MachineCode", machine_code);
//  add_argument(e, r, "FieldsToReturn", "0");
  cryptolens_RHP_add_argument(e, r, "SignMethod", "1");
  cryptolens_RHP_add_argument(e, r, "v", "1");

  char * response = cryptolens_RHP_perform(e, r);

  cryptolens_handle_activate_response(e, signature_verifier, response);

  free(response);
  cryptolens_RHP_destroy(r);
}
