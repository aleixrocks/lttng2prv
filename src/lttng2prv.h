#pragma once
#ifndef LTTNG2PRV_H
#define LTTNG2PRV_H

#define UNUSED(x) (void)(x)

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glib.h>
#include <libgen.h>
#include <popt.h>
#include <babeltrace/format.h>
#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/callbacks.h>

enum bt_cb_ret handle_exit_syscall(struct bt_ctf_event *_call_data,
    void *_private_data);

void getThreadInfo(struct bt_context *_ctx, uint32_t *_ncpus,
    GHashTable *_tid_info_ht, GHashTable *_tid_prv_ht, GList **_tid_prv_l,
    GHashTable *_irq_name_ht, uint32_t *_nsoftirqs,
    GHashTable *_irq_prv_ht, GList **_irq_prv_l, GHashTable *_lost_events_ht);

void printPRVHeader(struct bt_context *_ctx, FILE *_fp,
    GHashTable *_tid_info_ht, int _nresources);

void printROW(FILE *_fp, GHashTable *_tid_info_ht, GList *_tid_prv_l,
    GHashTable *_irq_name_ht, GList *_irq_prv_l, const uint32_t _ncpus,
    const uint32_t _nsoftirqs);

void printPCFHeader(FILE *_fp);

uint64_t bt_get_unsigned_int(const struct bt_definition *_field);

int64_t bt_get_signed_int(const struct bt_definition *_field);

void getArgValue(struct bt_ctf_event *_event, uint64_t _event_type,
    GHashTable *_arg_types_ht, char *_fields);

#endif

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=8 shiftwidth=8 expandtab cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */
