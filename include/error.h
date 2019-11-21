#pragma once

typedef struct cryptolens_error {
  // TODO: Change from int to uint64_t?
  int call;
  int subsystem;
  int reason;
  int extra;
} cryptolens_error_t;

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
