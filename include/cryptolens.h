#include "decode_base64.h"
#include "response_parser_cJSON.h"
#include "signature_verifier.h"

int handle_activate_response(error_t * e, signature_verifier_t * signature_verifier, char const* response);
