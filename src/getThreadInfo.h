#include <inttypes.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/callbacks.h>
#include <babeltrace/ctf/iterator.h>

int64_t bt_get_signed_int(const struct bt_definition *field);

uint64_t bt_get_unsigned_int(const struct bt_definition *field);
