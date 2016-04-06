#pragma once
#ifndef LISTEVENTS_H
#define LISTEVENTS_H

#include <stdlib.h>
#include <string.h>
#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/iterator.h>

#include "types.h"

void listEvents(struct bt_context *_bt_ctx, FILE *_fp);

#endif

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=9 shiftwidth=8
expandtab foldmethod=syntax cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */

