#include "cryptolens/error.h"

int
cryptolens_check_error(
  cryptolens_error_t * e
)
{
  return e->subsystem != 0;
}

void
cryptolens_reset_error(
  cryptolens_error_t * e
)
{
  e->subsystem = 0;
  e->reason = 0;
  e->extra = 0;
}

void
cryptolens_set_error(
  cryptolens_error_t * e,
  int subsystem,
  int reason,
  int extra
)
{
  e->subsystem = subsystem;
  e->reason = reason;
  e->extra = extra;
}

void
cryptolens_weak_set_error(
  cryptolens_error_t * e,
  int subsystem,
  int reason,
  int extra
)
{
  if (!cryptolens_check_error(e)) {
    cryptolens_set_error(e, subsystem, reason, extra);
  }
}
