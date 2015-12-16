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

static int parse_options(int argc, char **argv);

static struct poptOption long_options[] =
{
	{"output", 'o', POPT_ARG_STRING, NULL, OPT_OUTPUT, "Output file name", "FILE" },
	{"print-timestamps", 0, POPT_ARG_NONE, NULL, OPT_TIMESTAMPS, "Print trace start and end timestamps as linux epoch", NULL },
	{ "help", 'h', POPT_ARG_NONE, NULL, OPT_HELP, "Show this help message", NULL }
};

static int traverse_trace_dir(const char *fpath, const struct stat *sb, 
		int tflag, struct FTW *ftwbuf);

int bt_context_add_traces_recursive(struct bt_context *ctx, const char *path, 
		const char *format_str, void (*packet_seek)(struct bt_stream_pos *pos,
	 	size_t offset, int whence));

enum bt_cb_ret handle_exit_syscall(struct bt_ctf_event *call_data,
		void *private_data);

void getThreadInfo(struct bt_context *ctx, uint64_t *offset, uint32_t *ncpus,
		GHashTable *tid_info_ht, GHashTable *tid_prv_ht, GList **tid_prv_l,
	 	GHashTable *irq_name_ht, uint32_t *nsoftirqs,
		GHashTable *irq_prv_ht, GList **irq_prv_l);

void printPRVHeader(struct bt_context *ctx, uint64_t *offset, FILE *fp,
		GHashTable *tid_info_ht, int nresources);

void printROW(FILE *fp, GHashTable *tid_info_ht, GList *tid_prv_l,
	 	GHashTable *irq_name_ht, GList *irq_prv_l, const uint32_t ncpus,
	 	const uint32_t nsoftirqs);

void printPCFHeader(FILE *fp);

void iter_trace(struct bt_context *bt_ctx, uint64_t *offset, FILE *fp,
		GHashTable *tid_info_ht, GHashTable *tid_prv_ht, GHashTable *irq_name_ht,
		GHashTable *irq_prv_ht, const uint32_t ncpus, const uint32_t nsoftirqs,
		GHashTable *arg_types_ht);

void rmsubstr(char *dest, char *torm);

void list_events(struct bt_context *bt_ctx, FILE *fp);

uint64_t bt_get_unsigned_int(const struct bt_definition *field);

int64_t bt_get_signed_int(const struct bt_definition *field);

void getArgValue(struct bt_ctf_event *event, uint64_t event_type, GHashTable *arg_types_ht, char *fields);

void fillArgTypes(GHashTable *arg_types_ht);
