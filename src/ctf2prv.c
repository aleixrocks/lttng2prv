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
#include <babeltrace/babeltrace.h>
#include <babeltrace/context.h>
#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/callbacks.h>
#include <babeltrace/ctf/iterator.h>

//#include <babeltrace/ctf-writer/event.h>
//#include <babeltrace/ctf-writer/event-types.h>
//#include <babeltrace/ctf-writer/event-fields.h>
//#include <babeltrace/ctf-ir/event-fields-internal.h>
//#include <babeltrace/ctf-ir/event-types-internal.h>
//#include <babeltrace/ctf-ir/event-internal.h>
//#include <babeltrace/ctf-ir/stream-class.h>
//#include <babeltrace/ctf-ir/stream-class-internal.h>
//#include <babeltrace/ctf-ir/trace-internal.h>
//#include <babeltrace/ctf-ir/utils.h>
//#include <babeltrace/ref.h>
//#include <babeltrace/ctf-ir/attributes-internal.h>
//#include <babeltrace/compiler.h>

enum
{
	OPT_NONE = 0,
	OPT_OUTPUT,
	OPT_HELP
};

static char *opt_output;
const char *inputTrace, *outputTrace;

static struct bt_format *fmt_read;

static struct poptOption long_options[] =
{
	{"output", 'o', POPT_ARG_STRING, NULL, OPT_OUTPUT, NULL, NULL },
	{"help", 'h', POPT_ARG_NONE, NULL, OPT_HELP, NULL, NULL}
};

static void print_usage(FILE *fp)
{
	fprintf(fp, "CTF2PRV trace converter \n\n");
	fprintf(fp, "Usage: ctf2prv [OPTIONS] FILE\n");
	fprintf(fp, "\tFILE                   Input trace file\n");
	fprintf(fp, "\t-o, --output OUTPUT    Output file name\n");
	fprintf(fp, "\t-h, --help             Show this help\n");
	fprintf(fp, "\n");
}

static int parse_options(int argc, char **argv)
{
	poptContext pc;
	int opt, ret = 0;

	if (argc == 1)
	{
		print_usage(stdout);
		return 1;
	}

	pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);
	
	while ((opt = poptGetNextOpt(pc)) != -1)
	{
		switch (opt)
		{
			case OPT_OUTPUT:
				opt_output = (char *) poptGetOptArg(pc);
				if (!opt_output)
				{
					fprintf(stderr, "Wrong file name\n");
					opt = -1;
					ret = -EINVAL;
				}
				break;
			case OPT_HELP:
				print_usage(stdout);
				ret = 1;
				break;
			default:
				ret = -EINVAL;
				break;
		}
	}

	inputTrace = poptGetArg(pc);
	if (inputTrace == NULL)
	{
		ret = -EINVAL;
	}

	if (pc)	poptFreeContext(pc);

	return ret;
}

static GPtrArray *traversed_paths = 0;

static int traverse_trace_dir(const char *fpath, const struct stat *sb, 
		int tflag, struct FTW *ftwbuf)
{
	int dirfd, metafd;
	int closeret;

	if (tflag != FTW_D)
	{
		return 0;
	}

	dirfd = open(fpath, 0);
	if (dirfd < 0)
	{
		fprintf(stderr, "[error] [Context] Unable to open trace "
				"directory file desciptor.\n");
		return 0;
	}
	metafd = openat(dirfd, "metadata", O_RDONLY);
	if (metafd < 0)
	{
		closeret = close(dirfd);
		if (closeret < 0)
		{
			perror("close");
			return -1;
		}
		return 0;
	} else 
	{
		closeret = close(metafd);
		if (closeret < 0)
		{
			perror("close");
			return -1;
		}
		closeret = close(dirfd);
		if (closeret < 0)
		{
			perror("close");
			return -1;
		}

		if (traversed_paths == NULL)
		{
			fprintf(stderr, "[error] [Context] Invalid open path array.\n");
			return -1;
		}
		g_ptr_array_add(traversed_paths, g_string_new(fpath));
	}

	return 0;
}

int bt_context_add_traces_recursive(struct bt_context *ctx,
		const char *path, const char *format_str,
		void (*packet_seek)(struct bt_stream_pos *pos, size_t offset,
		int whence))
{
	GArray *trace_ids;
	int ret = 0;
	int i;

	traversed_paths = g_ptr_array_new();
	trace_ids = g_array_new(FALSE, TRUE, sizeof(int));

	ret = nftw(path, traverse_trace_dir, 10, 0);

	if (ret >= 0)
	{
		for (i = 0; i < traversed_paths->len; i++)
		{
			GString *trace_path = g_ptr_array_index(traversed_paths, i);
			int trace_id = bt_context_add_trace(ctx,
					trace_path->str,
					format_str,
					packet_seek,
					NULL,
					NULL);
			if (trace_id < 0)
			{
				fprintf(stderr, "[warning] [Context] cannot open trace \"%s\""
						"from %s for reading.\n", trace_path->str, path);
				ret = 1;
			} else
			{
				g_array_append_val(trace_ids, trace_id);
			}
			g_string_free(trace_path, TRUE);
		}
	}
	g_ptr_array_free(traversed_paths, TRUE);
	traversed_paths = NULL;

	if (trace_ids->len == 0)
	{
		fprintf(stderr, "[error] Cannot open any trace for reading.\n\n");
		ret = -ENOENT;
	}
	g_array_free(trace_ids, TRUE);
	return ret;
}

enum bt_cb_ret handle_exit_syscall(struct bt_ctf_event *call_data,
		void *private_data)
{
	const static struct bt_definition *scope;
	uint64_t ret;

	scope = bt_ctf_get_top_level_scope(call_data, BT_EVENT_FIELDS);
	ret = bt_ctf_get_int64(bt_ctf_get_field(call_data, scope, "_ret"));
	if (bt_ctf_field_get_error())
	{
		fprintf(stderr, "Error extracting ret\n");
		goto error;
	}

	printf("exit_syscall ret : %d, ", (int) ret);
	printf("int_signedness : %d\n", bt_ctf_get_encoding(
				bt_ctf_get_decl_from_def(bt_ctf_get_field(call_data, scope, "_ret"))));
	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

// Iterates through all events of the trace
void iter_trace(struct bt_context *bt_ctx, FILE *fp)
{
	struct bt_ctf_iter *iter;
	struct bt_iter_pos begin_pos;
	struct bt_ctf_event *event;
	char *prev_comm;
	const struct bt_definition *scope;
	int ret = 0;
	int flags;
	struct bt_definition **field_list;
	uint64_t cpu_id, appl_id, task_id, thread_id, init_time, state;
	struct bt_ctf_stream *stream;
	struct bt_ctf_field *packet_context;
	struct bt_ctf_field *fcpu_id;
	unsigned int *fcnt;

	begin_pos.type = BT_SEEK_BEGIN;
	iter = bt_ctf_iter_create(bt_ctx, &begin_pos, NULL);
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("exit_syscall"), NULL, 0,
			handle_exit_syscall, NULL, NULL, NULL);

	while ((event = bt_ctf_iter_read_event_flags(iter, &flags)) != NULL)
	{
		cpu_id = 1;
		appl_id = 1;
		task_id = 1;
		thread_id = 1;
		init_time = bt_ctf_get_timestamp(event);
		state=1;

/*		fprintf(fp, "ID: %s, TIME: %" PRIu64 "\n",
				bt_ctf_event_name(event),
				bt_ctf_get_timestamp(event));
*/
		if (flags) 
		{
			fprintf(stderr, "LOST : %" PRIu64 "\n", bt_ctf_get_lost_events_count(iter));
		}

		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
		cpu_id = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "cpu_id"));
		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_HEADER);
//		printf("%" PRIu64 "\n", bt_ctf_get_uint64(bt_ctf_get_enum_int(bt_ctf_get_field(event, scope, "id"))));
//
//		*********************************************
//		This is not the task_id, what is this number?
//		*********************************************
		task_id = bt_ctf_get_uint64(bt_ctf_get_enum_int(bt_ctf_get_field(event, scope, "id")));

/*
		if (strcmp(bt_ctf_event_name(event), "sched_switch") == 0)
		{
			scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
			prev_comm = bt_ctf_get_char_array(bt_ctf_get_field(
						event, scope, "_prev_comm")); if (bt_ctf_field_get_error()) { fprintf(stderr, "Missing prev_comm context info\n"); } fprintf(fp, "sched_switch prev_comm : %s\n", prev_comm);
		}
*/
		ret = bt_iter_next(bt_ctf_get_iter(iter));
		fprintf(fp, "1:%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n", cpu_id, appl_id, task_id, thread_id, init_time, bt_ctf_get_timestamp(event), state);

		if (ret < 0)
			goto end_iter;
	}

end_iter:
	bt_ctf_iter_destroy(iter);
}

// Prints list of event types
void list_events(struct bt_context *bt_ctx, FILE *fp)
{
//	int ret = 0;
	unsigned int cnt, i; //, fcnt;
	struct bt_ctf_event_decl *const * list;
	//struct bt_ctf_field_decl const * const **flist;
	uint64_t event_id;
	char *event_name;

	bt_ctf_get_event_decl_list(0, bt_ctx, &list, &cnt);
	for (i = 0; i < cnt; i++)
	{
//		if (bt_ctf_get_decl_fields(list[i], BT_EVENT_CONTEXT, flist, &fcnt) == -1);

		event_id = bt_ctf_get_decl_event_id(list[i]);
		event_name = bt_ctf_get_decl_event_name(list[i]);
		fprintf(fp, "%" PRIu64 " : %s\n", event_id, event_name);

//		fprintf(fp, "1:cpu_id:appl_id:%" PRIu64 ":thread_id:begin_time:end_time:state\n", task_id);
	}
}

//int trace_pre_handler(struct bt_trace_descriptor, struct bt_context);
//int convert_trace(struct bt_trace_descriptor, struct bt_context);
//int trace_post_handler(struct bt_trace_descriptor, struct bt_context);

int main(int argc, char **argv)
{
	int ret = 0;
	const char *format_str;
	struct bt_format *fmt_write;
	struct bt_trace_descriptor *td_write;
	struct bt_context *ctx;
	struct bt_iter_pos begin_pos;

	FILE *prv, *pcf;

	if (!opt_output)
	{
		prv = fopen("trace.prv", "w+");
	}else
	{
		prv = fopen(opt_output, "w+");
	}

	if (!opt_output)
	{
		pcf = fopen("trace.pcf", "w+");
	}else
	{
		pcf = fopen(opt_output, "w+");
	}

	ret = parse_options(argc, argv);
	if (ret < 0)
	{
		fprintf(stderr, "Error parsing options.\n\n");
		print_usage(stderr);
	}

	fmt_read = bt_lookup_format(g_quark_from_static_string(strdup("ctf")));
	ctx = bt_context_create();
	if (!ctx)
	{
		fprintf(stderr, "Couldn't create context.\n");
		goto end;
	}

	ret = bt_context_add_traces_recursive(ctx, inputTrace, "ctf", NULL);
	if (ret < 0)
	{
		fprintf(stderr, "Couldn't open trace \"%s\" for reading.\n", inputTrace);
		goto end;
	}

	time_t now = time(0);
	struct tm *local = localtime(&now);

	char day[3], mon[3], hour[3], min[3];
	sprintf(day, "%.2d", local->tm_mday);
	sprintf(mon, "%.2d", local->tm_mon + 1);
	sprintf(hour, "%.2d", local->tm_hour);
	sprintf(min, "%.2d", local->tm_min);

	uint64_t ftime = bt_trace_handle_get_timestamp_end(ctx, 0, BT_CLOCK_REAL)
		- bt_trace_handle_get_timestamp_begin(ctx, 0, BT_CLOCK_REAL);

	fprintf(prv, "#Paraver (%s/%s/%d at %s:%s):%" PRIu64 "_ns\n",
			day,
			mon,
			local->tm_year + 1900,
			hour,
			min,
			ftime
	);

	list_events(ctx, pcf);
	iter_trace(ctx, prv);

end:
	bt_context_put(ctx);
	fflush(prv);
	fflush(pcf);
	fclose(prv);
	fclose(pcf);
//	printf("Paraver trace %s generated", outputTrace);
	return 0;
}

/*
	ret = trace_pre_handler(td_write, ctx);
	if (ret)
	{
		fprintf(stderr, "Error in trace pre handle.\n\n");
		return 1;
	}

	if (fmt_read->name == g_quark_from_static_string("ctf"))
	{
		ret = convert_trace(td_write, ctx);
	}
	if (ret)
	{
		fprintf(stderr, "Error printing trace. \n\n");
		return 1;
	}

	ret = trace_post_handler(td_write, ctx);
	if (ret)
	{
		fprintf(stderr, "Error in trace post handle.\n\n");
		return 1;
	}
*/
