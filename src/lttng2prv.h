#define _GNU_SOURCE
#define __USE_XOPEN_EXTENDED
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <popt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <string.h>
#include <ftw.h>
#include <fts.h>
#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include <libgen.h>
#include <babeltrace/babeltrace.h>
#include <babeltrace/context.h>
#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/callbacks.h>
#include <babeltrace/ctf/iterator.h>
#include <babeltrace/format.h>

static int parse_options(int _argc, char **_argv);

static struct poptOption long_options[] =
{
        {"output", 'o', POPT_ARG_STRING, NULL, OPT_OUTPUT,
            "Output file name", "FILE" },
        {"print-timestamps", 0, POPT_ARG_NONE, NULL, OPT_TIMESTAMPS,
            "Print trace start and end timestamps as unix time", NULL },
        {"verbose", 'v', POPT_ARG_NONE, NULL, OPT_VERBOSE,
            "Be verbose", NULL },
        POPT_AUTOHELP
        {NULL, 0, 0, NULL, 0}
};

static int traverse_trace_dir(const char *_fpath, const struct stat *_sb,
    int _tflag, struct FTW *_ftwbuf);

int bt_context_add_traces_recursive(struct bt_context *_ctx, const char *_path,
    const char *_format_str, void (*packet_seek)(struct bt_stream_pos *pos,
    size_t offset, int whence));

enum bt_cb_ret handle_exit_syscall(struct bt_ctf_event *_call_data,
    void *_private_data);

void getThreadInfo(struct bt_context *_ctx, uint64_t *_offset, uint32_t *_ncpus,
    GHashTable *_tid_info_ht, GHashTable *_tid_prv_ht, GList **_tid_prv_l,
    GHashTable *_irq_name_ht, uint32_t *_nsoftirqs,
    GHashTable *_irq_prv_ht, GList **_irq_prv_l);

void printPRVHeader(struct bt_context *_ctx, uint64_t *_offset, FILE *_fp,
    GHashTable *_tid_info_ht, int _nresources);

void printROW(FILE *_fp, GHashTable *_tid_info_ht, GList *_tid_prv_l,
    GHashTable *_irq_name_ht, GList *_irq_prv_l, const uint32_t _ncpus,
    const uint32_t _nsoftirqs);

void printPCFHeader(FILE *_fp);

void iter_trace(struct bt_context *_bt_ctx, uint64_t *_offset, FILE *_fp,
    GHashTable *_tid_info_ht, GHashTable *_tid_prv_ht, GHashTable *_irq_name_ht,
    GHashTable *_irq_prv_ht, const uint32_t _ncpus, const uint32_t _nsoftirqs,
    GHashTable *_arg_types_ht);

void rmsubstr(char *_dest, char *_torm);

void list_events(struct bt_context *_bt_ctx, FILE *_fp);

uint64_t bt_get_unsigned_int(const struct bt_definition *_field);

int64_t bt_get_signed_int(const struct bt_definition *_field);

void getArgValue(struct bt_ctf_event *_event, uint64_t _event_type,
    GHashTable *_arg_types_ht, char *_fields);

void fillArgTypes(GHashTable *_arg_types_ht);

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=8 shiftwidth=8 expandtab cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */
