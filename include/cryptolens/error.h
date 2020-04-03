#pragma once

#define CRYPTOLENS_ES_OK 0
#define CRYPTOLENS_ES_MAIN 1
#define CRYPTOLENS_ES_RP 2
#define CRYPTOLENS_ES_BASE64 3
#define CRYPTOLENS_ES_RH 4
#define CRYPTOLENS_ES_SV 5

#define CRYPTOLENS_ER_DISABLED_API 11
#define CRYPTOLENS_ER_ALLOC_FAILED 12
#define CRYPTOLENS_ER_INVALID_SIGNATURE 13

#define CRYPTOLENS_ER_UNKNOWN_SERVER_REPLY 22
#define CRYPTOLENS_ER_INVALID_ACCESS_TOKEN 23
#define CRYPTOLENS_ER_ACCESS_DENIED 24
#define CRYPTOLENS_ER_INCORRECT_INPUT_PARAMETER 25
#define CRYPTOLENS_ER_PRODUCT_NOT_FOUND 26
#define CRYPTOLENS_ER_KEY_NOT_FOUND 27
#define CRYPTOLENS_ER_KEY_BLOCKED 28
#define CRYPTOLENS_ER_DEVICE_LIMIT_REACHED 29

typedef struct cryptolens_error {
  // TODO: Change from int to uint64_t?
  int call;
  int subsystem;
  int reason;
  int extra;
} cryptolens_error_t;

#ifdef __cplusplus
extern "C" {
#endif

int
cryptolens_check_error(
  cryptolens_error_t *
);

void
cryptolens_reset_error(
  cryptolens_error_t *
);

void
cryptolens_set_error(
  cryptolens_error_t *,
  int,
  int,
  int
);

void
cryptolens_weak_set_error(
  cryptolens_error_t *,
  int,
  int,
  int
);

#ifdef __cplusplus
}
#endif
