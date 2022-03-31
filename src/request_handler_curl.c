#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <curl/curl.h>

#define CRYPTOLENS_COMPILING
#include "cryptolens/error.h"
#include "cryptolens/request_handler.h"

static char const BASE_URL[] = "https://api.cryptolens.io/";

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
  cryptolens_error_t * e;
  char * response;
  size_t len;
  size_t pos;
} response_t;

cryptolens_RH_t *
cryptolens_RH_new(cryptolens_error_t * e)
{
  cryptolens_RH_t * o = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  o = malloc(sizeof(cryptolens_RH_t));
  if (!o) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 1); goto error; }

  o->curl = curl_easy_init();
  if (!o->curl) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, 2, 0); goto error; }

  goto end;

error:
  if (o) {
    curl_easy_cleanup(o->curl);
  }

  free(o);

end:
  return o;
}

void
cryptolens_RH_destroy(cryptolens_RH_t * o)
{
  if (o) {
    curl_easy_cleanup(o->curl);
  }

  free(o);
}

cryptolens_RHP_builder_t *
cryptolens_RHP_new(cryptolens_error_t *e, cryptolens_RH_t * rh, char const* method)
{
  cryptolens_RHP_builder_t * o = NULL;
  size_t n = 0;
  size_t m = 0;
  char * url = NULL;
  size_t pos = 0;

  if (cryptolens_check_error(e)) { goto error; }

  o = (cryptolens_RHP_builder_t *)malloc(sizeof(cryptolens_RHP_builder_t));
  if (!o) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 2); goto error; }
  n = strlen(BASE_URL);
  m = strlen(method);
  url = (char *)malloc(n + m + 1);
  if (!url) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 3); goto error; }

  pos = 0;
  for (size_t i = 0; i < n; ++i) { url[pos++] = BASE_URL[i]; }
  for (size_t i = 0; i < m; ++i) { url[pos++] = method[i]; }
  url[pos] = '\0';

  o->rh = rh;
  o->url = url;
  o->separator = ' ';
  o->postfields = NULL;
  o->postfields_len = 0;
  o->postfields_pos = 0;

  goto end;

error:
  free(url);
  free(o);

end:
  return o;
}

void
cryptolens_RHP_destroy(cryptolens_RHP_builder_t * o)
{
  if (o) {
    free(o->url);
    free(o->postfields);
  }

  free(o);
}

static
int
check_realloc(cryptolens_error_t * e, cryptolens_RHP_builder_t * o)
{
  if (o->postfields_pos == o->postfields_len) {
    size_t new_len = o->postfields_len == 0 ? 128 : 2*o->postfields_len;
    o->postfields = realloc(o->postfields, new_len);
    if (o->postfields == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 4); o->postfields_pos = 0; o->postfields_len = 0; return 1;}
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
    if(check_realloc(e, o)) { goto error; }
    o->postfields[o->postfields_pos++] = '&';
  }

  // TODO: key and value should be URL escaped
  while (*key != '\0') {
    if(check_realloc(e, o)) { goto error; }
    o->postfields[o->postfields_pos++] = *(key++);
  }

  if(check_realloc(e, o)) { goto error; }
  o->postfields[o->postfields_pos++] = '=';

  while (*value != '\0') {
    if(check_realloc(e, o)) { goto error; }
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
  if(check_realloc(e, o)) { goto error; }
  o->postfields[o->postfields_pos++] = '\0';

error:
end:
  return;
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
      if (r->response == NULL) { cryptolens_set_error(r->e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 5); r->pos = 0; r->len = 0; return 0; }
      r->len = new_len;
    }

    r->response[r->pos++] = ptr[i];
  }

  return size*nmemb;
}

static
void
null_terminate2(cryptolens_error_t * e, response_t * r)
{
  if (r->pos == r->len) {
    // TODO: Stupid to possibly double length when we are just adding a single character...
    size_t new_len = r->len == 0 ? 128 : 2*r->len;
    r->response = realloc(r->response, new_len);
    if (r->response == NULL) { cryptolens_set_error(r->e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 6); r->pos = 0; r->len = 0; return; }
    r->len = new_len;
  }

  r->response[r->pos++] = '\0';
}

char *
cryptolens_RHP_perform(cryptolens_error_t * e, cryptolens_RHP_builder_t * o)
{
  response_t * resp = NULL;
  char * response = NULL;

  if (cryptolens_check_error(e)) { goto error; }

  resp = malloc(sizeof(response_t));
  if (resp == NULL) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, CRYPTOLENS_ER_ALLOC_FAILED, 7); goto error; }

  resp->e = e;
  resp->response = NULL;
  resp->pos = 0;
  resp->len = 0;

  // TODO: Move this null termination somewhere else?
  //       In particular, we get incorrect result (but no memory errrors)
  //       if one tries to call perform() on the same builder after having
  //       added more arguments
  null_terminate(e, o);
  if (cryptolens_check_error(e)) { goto error; }

  CURLcode cc;
  cc = curl_easy_setopt(o->rh->curl, CURLOPT_URL, o->url);
  if (cc != CURLE_OK) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, 10, 3); goto error; }
  cc = curl_easy_setopt(o->rh->curl, CURLOPT_WRITEFUNCTION, handle_response);
  if (cc != CURLE_OK) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, 10, 4); goto error; }
  cc = curl_easy_setopt(o->rh->curl, CURLOPT_WRITEDATA, resp);
  if (cc != CURLE_OK) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, 10, 5); goto error; }
  cc = curl_easy_setopt(o->rh->curl, CURLOPT_POSTFIELDS, o->postfields);
  if (cc != CURLE_OK) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, 10, 6); goto error; }

  cc = curl_easy_perform(o->rh->curl);
  if (cc != CURLE_OK) { cryptolens_set_error(e, CRYPTOLENS_ES_RH, 10, 7); goto error; }

  null_terminate2(e, resp);
  if (cryptolens_check_error(e)) { goto error; }

  response = resp->response;

  goto end;

error:
  if (resp) {
    free(resp->response);
  }
  response = NULL;
end:
  free(resp);

  return response;
}
