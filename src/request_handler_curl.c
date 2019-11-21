#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <curl/curl.h>

#define CRYPTOLENS_COMPILING
#include "error.h"
#include "request_handler.h"

char const* BASE_URL = "https://app.cryptolens.io/";

struct cryptolens_RH {
  CURL *curl;
};

struct cryptolens_RHP_builder {
  cryptolens_RH_t * rh;

  char * url;
  char separator;
  char * postfields;
  size_t postfields_len;
  size_t postfields_pos;
};

typedef struct response {
  char * response;
  size_t len;
  size_t pos;
} response_t;

cryptolens_RH_t *
cryptolens_RH_new(cryptolens_error_t * e)
{
  cryptolens_RH_t * o = malloc(sizeof(cryptolens_RH_t));
  // TODO: NULL
  o->curl = curl_easy_init();  
  // TODO: NULL
}

void
cryptolens_RH_destroy(cryptolens_RH_t * o)
{
  curl_easy_cleanup(o->curl);
  free(o);
}

cryptolens_RHP_builder_t *
cryptolens_RHP_new(cryptolens_error_t *e, cryptolens_RH_t * rh, char const* method)
{
  cryptolens_RHP_builder_t * o = (cryptolens_RHP_builder_t *)malloc(sizeof(cryptolens_RHP_builder_t));

  size_t n = strlen(BASE_URL);
  size_t m = strlen(method);
  char * url = malloc(n + m + 1);
  if (url == NULL) { /* TODO: ... */ }

  size_t pos = 0;
  for (size_t i = 0; i < n; ++i) { url[pos++] = BASE_URL[i]; }
  for (size_t i = 0; i < m; ++i) { url[pos++] = method[i]; }
  url[pos] = '\0';

  o->rh = rh;
  o->url = url;
  o->separator = ' ';
  o->postfields = NULL;
  o->postfields_len = 0;
  o->postfields_pos = 0;

  return o;
}

void
cryptolens_RHP_destroy(cryptolens_RHP_builder_t * o)
{
  free(o->url);
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

static
size_t
handle_response(char * ptr, size_t size, size_t nmemb, void *userdata)
{
  response_t * r = (response_t *)userdata;
  for (size_t i = 0; i < size*nmemb; ++i) {
    if (r->pos == r->len) {
      size_t new_len = r->len == 0 ? 128 : 2*r->len;
      r->response = realloc(r->response, new_len);
      if (r->response == NULL) { /* TODO: Error checking */ }
      r->len = new_len;
    }

    r->response[r->pos++] = ptr[i];
  }

  return size*nmemb;
}

static
void
null_terminate2(response_t * r)
{
  if (r->pos == r->len) {
    // TODO: Stupid to possibly double length when we are just adding a single character...
    size_t new_len = r->len == 0 ? 128 : 2*r->len;
    r->response = realloc(r->response, new_len);
    if (r->response == NULL) { /* TODO: Error checking */ }
    r->len = new_len;
  }

  r->response[r->pos++] = '\0';
}

char *
cryptolens_RHP_perform(cryptolens_error_t * e, cryptolens_RHP_builder_t * o)
{
  response_t * resp = malloc(sizeof(response_t));
  if (resp == NULL) { /* TODO: Error checking */ }
  resp->response = NULL;
  resp->pos = 0;
  resp->len = 0;

  CURLcode cc;

  // TODO: Move this null termination somewhere else?
  //       In particular, we get incorrect result (but no memory errrors)
  //       if one tries to call perform() on the same builder after having
  //       added more arguments
  null_terminate(o);

  cc = curl_easy_setopt(o->rh->curl, CURLOPT_URL, o->url);
  // TODO: Error checking
  cc = curl_easy_setopt(o->rh->curl, CURLOPT_WRITEFUNCTION, handle_response);
  // TODO: Error checking
  cc = curl_easy_setopt(o->rh->curl, CURLOPT_WRITEDATA, resp);
  // TODO: Error checking
  cc = curl_easy_setopt(o->rh->curl, CURLOPT_POSTFIELDS, o->postfields);
  // TODO: Error checking

  cc = curl_easy_perform(o->rh->curl);
  // TODO: Error checking

  null_terminate2(resp);
  char * response = resp->response;
  free(resp);
  return response;
}
