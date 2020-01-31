#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <Windows.h>
#include <winhttp.h>

#define CRYPTOLENS_COMPILING
#include "error.h"
#include "request_handler.h"

char const* BASE_URL = "app.cryptolens.io";

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

cryptolens_RH_t *
cryptolens_RH_new(cryptolens_error_t * e)
{
  cryptolens_RH_t * o = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  o = malloc(sizeof(cryptolens_RH_t));
  if (o == NULL) { cryptolens_set_error(104, 298, 210); goto error; }

  o->hSession = WinHttpOpen( L"Cryptolens WinHTTP"
                           , WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
                           , WINHTTP_NO_PROXY_NAME
                           , WINHTTP_NO_PROXY_BYPASS
                           , 0
                           );
  if (o->hSession == NULL) { cryptolens_set_error(104, 298, 211); goto error; }

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
  size_t n;

  if (cryptolens_check_error(e)) { goto error; }

  o = (cryptolens_RHP_builder_t *)malloc(sizeof(cryptolens_RHP_builder_t));
  if (o == NULL) { cryptolens_set_error(e, 888, 1984, 22); goto error; }

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

static
void
check_realloc(cryptolens_error_t * e, cryptolens_RHP_builder_t * o)
{
  if (o->postfields_pos == o->postfields_len) {
    size_t new_len = o->postfields_len == 0 ? 128 : 2*o->postfields_len;
    o->postfields = realloc(o->postfields, new_len);
    if (o->postfields == NULL) { cryptolens_set_error(e, 23, 34, 98); o->postfields_pos = 0; o->postfields_len = 0; return 1;}
    o->postfields_len = new_len;
  }

  return 0;
}

void
cryptolens_RHP_add_argument(cryptolens_error_t * e, cryptolens_RHP_builder_t * o, char const* key, char const* value)
{
  if (cryptolens_check_error(e)) { goto error; }

  if (o->separator != '&') {
    o->separator = '&';
  } else {
    if (check_realloc(e, o)) { goto error; }
    o->postfields[o->postfields_pos++] = '&';
  }

  // TODO: key and value should be URL escaped
  //       maybe just add my own function which does this inline so to speak?
  //       instead of allocating an entierly new string, just to do it once more
  while (*key != '\0') {
    if (check_realloc(e, o)) { goto error; }
    o->postfields[o->postfields_pos++] = *(key++);
  }

  if (check_realloc(e, o)) { goto error; }
  o->postfields[o->postfields_pos++] = '=';

  while (*value != '\0') {
    if (check_realloc(e, o)) { goto error; }
    o->postfields[o->postfields_pos++] = *(value++);
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
  if (check_realloc(e, o)) { goto error; }
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
                               , NULL
                               );
  if (!result) { cryptolens_set_error(e, 298, 10, 41); goto error; }

  result = WinHttpReceiveResponse(hRequest, NULL);
  if (!result) { cryptolens_set_error(e, 298, 10, 42); goto error; }

  size_t bytes;
  while(1) {
    bytes = 0;
    result = WinHttpQueryDataAvailable(hRequest, &bytes);
    if (!result) { cryptolens_set_error(e, 298, 10, 43); goto error; }

    if (bytes == 0) { break; }

    if (len - pos < bytes) {
      size_t new_len = len == 0 ? 128 : 2*len;
      if (new_len - pos < bytes) { new_len = pos + bytes; }

      response = realloc(response, new_len);
      if (!response) { cryptolens_set_error(e, 298, 10, 44); pos = 0; len = 0; goto error; }
      len = new_len;
    }

    result = WinHttpReadData(hRequest, response + pos, bytes, NULL);
    if (!result) { cryptolens_set_error(e, 298, 10, 45); goto error; }

    pos += bytes;
  }

//  null_terminate2(resp);
  if (pos == len) { response = realloc(response, len + 1); }
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
