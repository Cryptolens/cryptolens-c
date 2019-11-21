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
  cryptolens_RH_t * o = malloc(sizeof(cryptolens_RH_t));
  // TODO: NULL
  o->hSession = WinHttpOpen( L"Cryptolens WinHTTP"
                           , WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
                           , WINHTTP_NO_PROXY_NAME
                           , WINHTTP_NO_PROXY_BYPASS
                           , 0
                           );
  // TODO: NULL
  return o;

error:
  if (o) {
    if (o->hSession) { WinHttpCloseHandle(o->hSession); }
    free(o);
  }
  return NULL;
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
  cryptolens_RHP_builder_t * o = (cryptolens_RHP_builder_t *)malloc(sizeof(cryptolens_RHP_builder_t));
  size_t n;

  n = MultiByteToWideChar(CP_UTF8, 0, BASE_URL, -1, NULL, 0);
  // TODO: Check n is 0
  o->host = malloc(n * sizeof(wchar_t));
  // TODO: Check NULL
  MultiByteToWideChar(CP_UTF8, 0, BASE_URL, -1, o->host, n);

  n = MultiByteToWideChar(CP_UTF8, 0, method, -1, NULL, 0);
  // TODO: Check n is 0
  o->endpoint = malloc(n * sizeof(wchar_t));
  // TODO: Check NULL
  MultiByteToWideChar(CP_UTF8, 0, method, -1, o->endpoint, n);

  o->rh = rh;
  o->separator = ' ';
  o->postfields = NULL;
  o->postfields_len = 0;
  o->postfields_pos = 0;

  return o;
}

void
cryptolens_RHP_destroy(cryptolens_RHP_builder_t * o)
{
  free(o->host);
  free(o->endpoint);
  free(o->postfields);
  free(o);
}

static
void
check_realloc(cryptolens_RHP_builder_t * o)
{
  if (o->postfields_pos == o->postfields_len) {
    size_t new_len = o->postfields_len == 0 ? 128 : 2*o->postfields_len;
    o->postfields = realloc(o->postfields, new_len);
    if (o->postfields == NULL) { /* TODO: Error checking */ }
    o->postfields_len = new_len;
  }
}

void
cryptolens_RHP_add_argument(cryptolens_error_t * e, cryptolens_RHP_builder_t * o, char const* key, char const* value)
{
  if (o->separator != '&') {
    o->separator = '&';
  } else {
    check_realloc(o);
    o->postfields[o->postfields_pos++] = '&';
  }

  // TODO: key and value should be URL escaped
  //       maybe just add my own function which does this inline so to speak?
  //       instead of allocating an entierly new string, just to do it once more
  while (*key != '\0') {
    check_realloc(o);
    o->postfields[o->postfields_pos++] = *(key++);
  }

  check_realloc(o);
  o->postfields[o->postfields_pos++] = '=';

  while (*value != '\0') {
    check_realloc(o);
    o->postfields[o->postfields_pos++] = *(value++);
  }
}

static
void
null_terminate(cryptolens_RHP_builder_t * o)
{
  check_realloc(o);
  o->postfields[o->postfields_pos++] = '\0';
}

char *
cryptolens_RHP_perform(cryptolens_error_t * e, cryptolens_RHP_builder_t * o)
{
  unsigned char * response = NULL;
  size_t pos = 0;
  size_t len = 0;

  HINTERNET hConnect = NULL,
            hRequest = NULL;

  int result;

  // TODO: Move this null termination somewhere else?
  //       In particular, we get incorrect result (but no memory errrors)
  //       if one tries to call perform() on the same builder after having
  //       added more arguments
  null_terminate(o);


  hConnect = WinHttpConnect(o->rh->hSession, o->host, INTERNET_DEFAULT_HTTPS_PORT, 0);
  //if (!hConnect) { e.set(api, Subsystem::RequestHandler, err::WINHTTP_CONNECT_FAILED, GetLastError()); goto cleanup; }

  hRequest = WinHttpOpenRequest( hConnect
                               , L"POST"
                               , o->endpoint
                               , NULL
                               , WINHTTP_NO_REFERER
                               , WINHTTP_DEFAULT_ACCEPT_TYPES
                               , WINHTTP_FLAG_SECURE
                               );
  //if (!hRequest) { e.set(api, Subsystem::RequestHandler, err::WINHTTP_OPEN_REQUEST_FAILED, GetLastError()); goto cleanup; }

  // TODO: Casting to DWORD
  result =  WinHttpSendRequest( hRequest
                               , L"Content-Type: application/x-www-form-urlencoded"
                               , -1L
                               , (LPVOID *)o->postfields
                               , (DWORD)o->postfields_pos
                               , (DWORD)o->postfields_pos
                               , NULL
                               );
  //if (!result) { e.set(api, Subsystem::RequestHandler, err::WINHTTP_SEND_REQUEST_FAILED, GetLastError()); goto cleanup; }

  result = WinHttpReceiveResponse(hRequest, NULL);
  //if (!result) { e.set(api, Subsystem::RequestHandler, err::WINHTTP_RECIEVE_RESPONSE_FAILED, GetLastError()); goto cleanup; }
  size_t bytes;
  while(1) {
    bytes = 0;
    result = WinHttpQueryDataAvailable(hRequest, &bytes);
    //if (!result) { e.set(api, Subsystem::RequestHandler, err::WINHTTP_QUERY_DATA_AVAILABLE_FAILED, GetLastError()); goto cleanup; }

    if (bytes == 0) { break; }

    if (len - pos < bytes) {
      size_t new_len = len == 0 ? 128 : 2*len;
      if (new_len - pos < bytes) { new_len = pos + bytes; }

      response = realloc(response, new_len);
      if (response == NULL) { /* TODO: Error checking */ }
      len = new_len;
    }

    result = WinHttpReadData(hRequest, response + pos, bytes, NULL);
    //if (!result) { e.set(api, Subsystem::RequestHandler, err::WINHTTP_READ_DATA_FAILED, GetLastError()); goto cleanup; }

    pos += bytes;
  }

cleanup:
  if(hRequest) { WinHttpCloseHandle(hRequest); }
  if(hConnect) { WinHttpCloseHandle(hConnect); }

//  null_terminate2(resp);
  if (pos == len) { response = realloc(response, len + 1); }
  response[pos] = '\0'; // TODO: May be invalid
  return response;
}