#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <Windows.h>
#include <winhttp.h>

#define CRYPTOLENS_COMPILING
#include "cryptolens/error.h"
#include "cryptolens/request_handler.h"

static char const BASE_URL[] = "api.cryptolens.io";

struct cryptolens_RH {
  HINTERNET hSession;
};

struct cryptolens_RHP_builder {
  cryptolens_RH_t * rh;

  LPWSTR host;
  LPWSTR endpoint;

  char separator;
  char * postfields;
  size_t postfields_len;
  size_t postfields_pos;
};

static
int
check_realloc(cryptolens_error_t* e, char** p, size_t* pos, size_t* len, size_t n)
{
    if (*pos + n >= *len) {
        size_t new_len = *len == 0 ? max(128, n) : max(*len + n, 2 * (*len));
        *p = realloc(*p, new_len);
        if (*p == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 3); *pos = 0; *len = 0; return 1; }
        *len = new_len;
    }

    return 0;
}

static
int
check_realloco(cryptolens_error_t* e, cryptolens_RHP_builder_t * o, size_t n) {
    return check_realloc(e, &o->postfields, &o->postfields_pos, &o->postfields_len, 1);
}

static
int
percent_encode(cryptolens_error_t* e, cryptolens_RHP_builder_t * o, char c)
{
  char HEX[] = "0123456789ABCDEF";
  int r = 0;

  switch (c) {
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I': case 'J': case 'K': case 'L': case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T': case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g': case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': case 'n': case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
    case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
    case '-': case '.': case '_': case '~':
        r = check_realloco(e, o, 1); if (r) { return r; }
        o->postfields[o->postfields_pos++] = c;
    break;

    default:
        r = check_realloco(e, o, 3); if (r) { return r; }
        o->postfields[o->postfields_pos++] = '%';
        o->postfields[o->postfields_pos++] = HEX[(c >> 4) & 0xF];
        o->postfields[o->postfields_pos++] = HEX[(c >> 0) & 0xF];
  }

  return r;
}

static
int
percent_encodeo(cryptolens_error_t * e, cryptolens_RHP_builder_t * o, char c)
{
  return percent_encode(e, o, c);
  //return percent_encode(e, &o->postfields, &o->postfields_pos, &o->postfields_len);
}

cryptolens_RH_t *
cryptolens_RH_new(cryptolens_error_t * e)
{
  cryptolens_RH_t * o = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  o = malloc(sizeof(cryptolens_RH_t));
  if (o == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 1); goto error; }

  o->hSession = WinHttpOpen( L"Cryptolens WinHTTP"
                           , WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
                           , WINHTTP_NO_PROXY_NAME
                           , WINHTTP_NO_PROXY_BYPASS
                           , 0
                           );
  if (o->hSession == NULL) { cryptolens_set_error(e, 104, 298, 211); goto error; }

  goto end;

error:
  if (o) {
    if (o->hSession) { WinHttpCloseHandle(o->hSession); }
    free(o);
  }

  o = NULL;

end:
  return o;
}

void
cryptolens_RH_destroy(cryptolens_RH_t * o)
{
  if (o->hSession) { WinHttpCloseHandle(o->hSession); }
  free(o);
}

cryptolens_RHP_builder_t *
cryptolens_RHP_new(cryptolens_error_t *e, cryptolens_RH_t * rh, char const* method)
{
  cryptolens_RHP_builder_t * o = NULL;
  int n;

  if (cryptolens_check_error(e)) { goto error; }

  o = (cryptolens_RHP_builder_t *)malloc(sizeof(cryptolens_RHP_builder_t));
  if (o == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 2); goto error; }

  n = MultiByteToWideChar(CP_UTF8, 0, BASE_URL, -1, NULL, 0);
  if (n == 0) { cryptolens_set_error(e, 888, 1984, 23); goto error; }
  o->host = malloc(n * sizeof(wchar_t));
  if (o->host == NULL) { cryptolens_set_error(e, 888, 1984, 24); goto error; }
  n = MultiByteToWideChar(CP_UTF8, 0, BASE_URL, -1, o->host, n);
  if (n == 0) { cryptolens_set_error(e, 888, 1984, 25); goto error; }

  n = MultiByteToWideChar(CP_UTF8, 0, method, -1, NULL, 0);
  if (n == 0) { cryptolens_set_error(e, 888, 1984, 26); goto error; }
  o->endpoint = malloc(n * sizeof(wchar_t));
  if (o->endpoint == NULL) { cryptolens_set_error(e, 888, 1984, 27); goto error; }
  n = MultiByteToWideChar(CP_UTF8, 0, method, -1, o->endpoint, n);
  if (n == 0) { cryptolens_set_error(e, 888, 1984, 28); goto error; }

  o->rh = rh;
  o->separator = ' ';
  o->postfields = NULL;
  o->postfields_len = 0;
  o->postfields_pos = 0;

  goto end;

error:
  if (o) {
    free(o->host);
    free(o->endpoint);
  }

  free(o);
  o = NULL;

end:
  return o;
}

void
cryptolens_RHP_destroy(cryptolens_RHP_builder_t * o)
{
  if (o) {
    free(o->host);
    free(o->endpoint);
    free(o->postfields);
  }

  free(o);
}

void
cryptolens_RHP_add_argument(cryptolens_error_t * e, cryptolens_RHP_builder_t * o, char const* key, char const* value)
{
  if (cryptolens_check_error(e)) { goto error; }

  if (key == NULL || value == NULL) { return; }

  if (o->separator != '&') {
    o->separator = '&';
  } else {
    if (check_realloco(e, o, 1)) { goto error; }
    o->postfields[o->postfields_pos++] = '&';
  }

  while (*key != '\0') {
    if (percent_encodeo(e, o, *(key++))) { goto error; };
//    if (check_realloco(e, o)) { goto error; }
//    o->postfields[o->postfields_pos++] = *(key++);
  }

  if (check_realloco(e, o, 1)) { goto error; }
  o->postfields[o->postfields_pos++] = '=';

  while (*value != '\0') {
    if (percent_encodeo(e, o, *(value++))) { goto error; };
  }

  goto end;

error:
end:
  return;
}

static
void
null_terminate(cryptolens_error_t * e, cryptolens_RHP_builder_t * o)
{
  if (check_realloco(e, o, 1)) { goto error; }
  o->postfields[o->postfields_pos++] = '\0';

  goto end;

error:
end:
  return;
}

char *
cryptolens_RHP_perform(cryptolens_error_t * e, cryptolens_RHP_builder_t * o)
{
  unsigned char * response = NULL;
  size_t pos = 0;
  size_t len = 0;

  HINTERNET hConnect = NULL;
  HINTERNET hRequest = NULL;

  int result;

  if (cryptolens_check_error(e)) { goto error; }

  // TODO: Move this null termination somewhere else?
  //       In particular, we get incorrect result (but no memory errrors)
  //       if one tries to call perform() on the same builder after having
  //       added more arguments
  null_terminate(e, o);
  if (cryptolens_check_error(e)) { goto error; }


  hConnect = WinHttpConnect(o->rh->hSession, o->host, INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!hConnect) { cryptolens_set_error(e, 298, 10, 39); goto error; }

  hRequest = WinHttpOpenRequest( hConnect
                               , L"POST"
                               , o->endpoint
                               , NULL
                               , WINHTTP_NO_REFERER
                               , WINHTTP_DEFAULT_ACCEPT_TYPES
                               , WINHTTP_FLAG_SECURE
                               );
  if (!hRequest) { cryptolens_set_error(e, 298, 10, 40); goto error; }

  // TODO: Casting to DWORD
  result =  WinHttpSendRequest( hRequest
                               , L"Content-Type: application/x-www-form-urlencoded"
                               , -1L
                               , (LPVOID *)o->postfields
                               , (DWORD)o->postfields_pos
                               , (DWORD)o->postfields_pos
                               , (DWORD_PTR)0 //NULL
                               );
  if (!result) { cryptolens_set_error(e, 298, 10, 41); goto error; }

  result = WinHttpReceiveResponse(hRequest, NULL);
  if (!result) { cryptolens_set_error(e, 298, 10, 42); goto error; }

  DWORD bytes;
  while(1) {
    bytes = 0;
    result = WinHttpQueryDataAvailable(hRequest, &bytes);
    if (!result) { cryptolens_set_error(e, 298, 10, 43); goto error; }

    if (bytes == 0) { break; }

    if (len - pos < bytes) {
      size_t new_len = len == 0 ? 128 : 2*len;
      if (new_len - pos < bytes) { new_len = pos + bytes; }

      response = realloc(response, new_len);
      if (!response) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 4); pos = 0; len = 0; goto error; }
      len = new_len;
    }

    result = WinHttpReadData(hRequest, response + pos, bytes, NULL);
    if (!result) { cryptolens_set_error(e, 298, 10, 45); goto error; }

    pos += bytes;
  }

  if (pos == len) {
    response = realloc(response, len + 1);
    if (!response) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 5); goto error; }
  }
  response[pos++] = '\0';

  goto end;

error:
  free(response);
  response = NULL;
  pos = 0;
  len = 0;
end:
  if(hRequest) { WinHttpCloseHandle(hRequest); }
  if(hConnect) { WinHttpCloseHandle(hConnect); }

  return response;
}
