#pragma once
#ifndef GETTHREADINFO_H
#define GETTHREADINFO_H

#define UNUSED(x) (void)(x)

#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/callbacks.h>
#include <babeltrace/ctf/iterator.h>

int64_t bt_get_signed_int(const struct bt_definition *_field);

uint64_t bt_get_unsigned_int(const struct bt_definition *_field);

#endif

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=8 shiftwidth=8 expandtab cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */
