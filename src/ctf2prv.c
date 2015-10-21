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

#include <babeltrace/format.h>

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

struct traceTimes
{
	uint64_t first_stream_timestamp;
	uint64_t last_stream_timestamp;
};

struct traceTimes trace_times;
uint64_t offset;

struct Events
{
	uint64_t id;
	char *name;
	struct Events *next;
};

static void print_usage(FILE *fp)
{
	fprintf(fp, "CTF2PRV trace converter \n\n");
	fprintf(fp, "Usage: ctf2prv [OPTIONS] FILE\n");
	fprintf(fp, "\tFILE                   Input trace file\n");
//	fprintf(fp, "\t-o, --output OUTPUT    Output file name\n");
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

void printPRVHeader(struct bt_context *ctx, FILE *fp)
{
	struct bt_iter_pos begin_pos;
	struct bt_ctf_iter *iter;
	struct bt_ctf_event *event;
	int flags;
	int ret = 0;

	const struct bt_definition *scope;
	uint64_t init_time_old, end_time_old;

	begin_pos.type = BT_SEEK_BEGIN;
	iter = bt_ctf_iter_create(ctx, &begin_pos, NULL);
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("exit_syscall"), NULL, 0,
			handle_exit_syscall, NULL, NULL, NULL);

	trace_times.first_stream_timestamp = 0;
	trace_times.last_stream_timestamp = 0;
	offset = 0;

	while ((event = bt_ctf_iter_read_event_flags(iter, &flags)) != NULL)
	{
		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
		if (trace_times.first_stream_timestamp > bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_begin")) || trace_times.first_stream_timestamp == 0)
		{
			trace_times.first_stream_timestamp = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_begin"));
		}
		if (trace_times.last_stream_timestamp < bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_end")) || trace_times.last_stream_timestamp == 0)
		{
			trace_times.last_stream_timestamp = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_end"));
		}

		if (offset > bt_ctf_get_timestamp(event) || offset == 0)
		{
			offset = bt_ctf_get_timestamp(event);
		}


		ret = bt_iter_next(bt_ctf_get_iter(iter));

		if (ret < 0)
			goto end_iter;
	}

	offset -= trace_times.first_stream_timestamp;

	time_t now = time(0);
	struct tm *local = localtime(&now);
	uint64_t ftime = trace_times.last_stream_timestamp - trace_times.first_stream_timestamp;
	//uint64_t ftime = bt_trace_handle_get_timestamp_end(ctx, 0, BT_CLOCK_REAL) - bt_trace_handle_get_timestamp_begin(ctx, 0, BT_CLOCK_REAL);

	char day[3], mon[3], hour[3], min[3];
	sprintf(day, "%.2d", local->tm_mday);
	sprintf(mon, "%.2d", local->tm_mon + 1);
	sprintf(hour, "%.2d", local->tm_hour);
	sprintf(min, "%.2d", local->tm_min);

	fprintf(fp, "#Paraver (%s/%s/%d at %s:%s):%" PRIu64 "_ns:1(16):1:1(16:1),1\nc:1:1:1:1\n",
			day,
			mon,
			local->tm_year + 1900,
			hour,
			min,
			ftime
	);


end_iter:
	bt_ctf_iter_destroy(iter);
}

// Iterates through all events of the trace
void iter_trace(struct bt_context *bt_ctx, FILE *fp)
{
	unsigned int NCPUS = 16;
	struct bt_ctf_iter *iter;
	struct bt_iter_pos begin_pos;
	struct bt_ctf_event *event;
	char *prev_comm;
	const struct bt_definition *scope;
	int ret = 0;
	int flags;
	uint64_t appl_id, task_id, thread_id, init_time, end_time, state, event_time;
	uint32_t cpu_id, stream_id, prev_stream_id = -1;
	uint64_t event_type, event_value, offset_stream;
	uint32_t old_cpu_id = -1;
	uint64_t cpu_thread[NCPUS];
	unsigned int i = 0;

	for (i = 0; i<16; i++)
	{
		cpu_thread[i] = i + 1;
	}

	begin_pos.type = BT_SEEK_BEGIN;
	iter = bt_ctf_iter_create(bt_ctx, &begin_pos, NULL);
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("exit_syscall"), NULL, 0,
			handle_exit_syscall, NULL, NULL, NULL);

	while ((event = bt_ctf_iter_read_event_flags(iter, &flags)) != NULL)
	{
		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
		cpu_id = bt_get_unsigned_int(bt_ctf_get_field(event, scope, "cpu_id")) + 1;
		appl_id = 1;
		task_id = 1;

/**************************** State Records ***************************/

		if (strstr(bt_ctf_event_name(event), "sched_switch") != NULL)
		{
			scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
			cpu_thread[cpu_id] = bt_get_signed_int(bt_ctf_get_field(event, scope, "_next_tid"));
			if (cpu_thread[cpu_id] == 0) cpu_thread[cpu_id] = cpu_id + 1;
		}

		if (old_cpu_id == -1 || old_cpu_id != cpu_id)
		{
			old_cpu_id = cpu_id;

//			offset = 1443443077719118246;		// Get offset from clock metadata
			offset_stream = trace_times.first_stream_timestamp;

			scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
			init_time = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_begin"));
			end_time = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_end")) - init_time;
			init_time = init_time - offset_stream;

			state = 1;
	
			fprintf(fp, "1:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n", cpu_id, appl_id, task_id, cpu_thread[cpu_id - 1], init_time, end_time, state);
		}

/**************************** /State Records **************************/

/**************************** Event Records ***************************/

		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
		event_time = bt_ctf_get_timestamp(event) - offset - offset_stream;

		if (strstr(bt_ctf_event_name(event), "syscall") != NULL)
		{
			event_type = 100000000;
		}else
		{
			event_type = 200000000;
		}

		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_HEADER);
		if (strstr(bt_ctf_event_name(event), "syscall_exit_") != NULL)
		{
			event_value = 0;
		}else
		{
			event_value = bt_ctf_get_uint64(bt_ctf_get_enum_int(bt_ctf_get_field(event, scope, "id")));
		}
		
/*****		 ID for value == 65536 in extended metadata		*****/
		if (event_value == 65535)
		{
			event_value = bt_ctf_get_uint64(bt_ctf_get_struct_field_index(bt_ctf_get_field(event, scope, "v"), 0));
		}

		fprintf(fp, "2:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n", cpu_id, appl_id, task_id, cpu_thread[cpu_id - 1], event_time, event_type, event_value);


/*************************** /Event Records ***************************/

		if (flags) 
		{
			fprintf(stderr, "LOST : %" PRIu64 "\n", bt_ctf_get_lost_events_count(iter));
		}

/*
		if (strcmp(bt_ctf_event_name(event), "sched_switch") == 0)
		{
			scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
			prev_comm = bt_ctf_get_char_array(bt_ctf_get_field(
						event, scope, "_prev_comm")); if (bt_ctf_field_get_error()) { fprintf(stderr, "Missing prev_comm context info\n"); } fprintf(fp, "sched_switch prev_comm : %s\n", prev_comm);
		}
*/
//		fprintf(fp, "1:%" PRIu32 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n", cpu_id, appl_id, task_id, thread_id, init_time, end_time, state);
		ret = bt_iter_next(bt_ctf_get_iter(iter));

		if (ret < 0)
			goto end_iter;
	}

end_iter:
	bt_ctf_iter_destroy(iter);
}

// Removes substring torm from input string dest
void rmsubstr(char *dest, char *torm)
{
	if ((dest = strstr(dest, torm)) != NULL)
	{
		const size_t len = strlen(torm);
		char *copyEnd;
		char *copyFrom = dest + len;

		while ((copyEnd = strstr(copyFrom, torm)) != NULL)
		{  
			memmove(dest, copyFrom, copyEnd - copyFrom);
			dest += copyEnd - copyFrom;
			copyFrom = copyEnd + len;
		}
		memmove(dest, copyFrom, 1 + strlen(copyFrom));
	}
}

// Prints list of event types
void list_events(struct bt_context *bt_ctx, FILE *fp)
{
	unsigned int cnt, i;
	struct bt_ctf_event_decl *const * list;
	uint64_t event_id;
	char *event_name;
	struct Events *syscalls_root;
	struct Events *syscalls;
	struct Events *kerncalls_root;
	struct Events *kerncalls;

	syscalls_root = (struct Events *) malloc(sizeof(struct Events));
	syscalls_root->next = NULL;
	syscalls = syscalls_root;

	kerncalls_root = (struct Events *) malloc(sizeof(struct Events));
	kerncalls_root->next = NULL;
	kerncalls = kerncalls_root;

	bt_ctf_get_event_decl_list(0, bt_ctx, &list, &cnt);
	for (i = 0; i < cnt; i++)
	{
		event_id = bt_ctf_get_decl_event_id(list[i]);
		event_name = bt_ctf_get_decl_event_name(list[i]);

 		if (strstr(event_name, "syscall_entry") != NULL) {
 			syscalls->id = event_id;

			/* Careful with this call, moves memory positions and may result
			 * in malfunction. See comment at the end of main.
			 */ 
 			rmsubstr(event_name, "syscall_entry_");
 			syscalls->name = (char *) malloc(strlen(event_name) + 1);
 			strncpy(syscalls->name, event_name, strlen(event_name) + 1);
 			syscalls->next = (struct Events *) malloc(sizeof(struct Events));
 			syscalls = syscalls->next;
 			syscalls->next = NULL;
 		} else if (strstr(event_name, "syscall_exit") == NULL)
 		{
 			kerncalls->id = event_id;
 			kerncalls->name = (char *) malloc(strlen(event_name) + 1);
 			strncpy(kerncalls->name, event_name, strlen(event_name) + 1);
 			kerncalls->next = (struct Events*) malloc(sizeof(struct Events));
 			kerncalls = kerncalls->next;
 			kerncalls->next = NULL;
 		}
 	}
 
	fprintf(fp, "EVENT_TYPE\n"
			"0\t100000000\tSystem Call\n"
			"VALUES\n");

 	syscalls = syscalls_root;
 	while(syscalls->next != NULL)
 	{
 		fprintf(fp, "%" PRIu64 "\t%s\n", syscalls->id, syscalls->name);
 		syscalls = syscalls->next;
 	}
	fprintf(fp, "0\texit\n\n\n");

	fprintf(fp, "EVENT_TYPE\n"
			"0\t200000000\tKernel Event\n"
			"VALUES\n");

	kerncalls = kerncalls_root;
	while(kerncalls->next != NULL)
	{
		fprintf(fp, "%" PRIu64 "\t%s\n", kerncalls->id, kerncalls->name);
		kerncalls = kerncalls->next;
	}

	free(syscalls_root);
	free(syscalls);
	free(kerncalls_root);
	free(kerncalls);
}

void printPCFHeader(FILE *fp)
{
	fprintf(fp,
			"DEFAULT_OPTIONS\n\n"
			"LEVEL\t\t\tTHREAD\n"
			"UNITS\t\t\tNANOSEC\n"
			"LOOK_BACK\t\t100\n"
			"SPEED\t\t\t1\n"
			"FLAG_ICONS\t\tENABLED\n"
			"NUM_OF_STATE_COLORS\t1000\n"
			"YMAX_SCALE\t\t37\n\n\n"
			"DEFAULT_SEMANTIC\n\n"
			"THREAD_FUNC\t\tState As Is\n\n\n");

	fprintf(fp,
			"STATES\n"
			"0\t\tIdle\n"
			"1\t\tRunning\n"
			"2\t\tNot created\n"
			"3\t\tWaiting a message\n"
			"4\t\tBlocking Send\n"
			"5\t\tSynchronization\n"
			"6\t\tTest/Probe\n"
			"7\t\tScheduling and Fork/Join\n"
			"8\t\tWait/WaitAll\n"
			"9\t\tBlocked\n"
			"10\t\tImmediate Send\n"
			"11\t\tImmediate Receive\n"
			"12\t\tI/O\n"
			"13\t\tGroup Communication\n"
			"14\t\tTracing Disabled\n"
			"15\t\tOthers\n"
			"16\t\tSend Receive\n"
			"17\t\tMemory transfer\n"
			"18\t\tProfiling\n"
			"19\t\tOn-line analysis\n"
			"20\t\tRemote memory access\n"
			"21\t\tAtomic memory operation\n"
			"22\t\tMemory ordering operation\n"
			"23\t\tDistributed locking\n\n\n");

	fprintf(fp,
			"STATES_COLOR\n"
			"0\t\t{117,195,255}\n"
			"1\t\t{0,0,255}\n"
			"2\t\t{255,255,255}\n"
			"3\t\t{255,0,0}\n"
			"4\t\t{255,0,174}\n"
			"5\t\t{179,0,0}\n"
			"6\t\t{0,255,0}\n"
			"7\t\t{255,255,0}\n"
			"8\t\t{235,0,0}\n"
			"9\t\t{0,162,0}\n"
			"10\t\t{255,0,255}\n"
			"11\t\t{100,100,177}\n"
			"12\t\t{172,174,41}\n"
			"13\t\t{255,144,26}\n"
			"14\t\t{2,255,177}\n"
			"15\t\t{192,224,0}\n"
			"16\t\t{66,66,66}\n"
			"17\t\t{255,0,96}\n"
			"18\t\t{169,169,169}\n"
			"19\t\t{169,0,0}\n"
			"20\t\t{0,109,255}\n"
			"21\t\t{200,61,68}\n"
			"22\t\t{200,66,0}\n"
			"23\t\t{0,41,0}\n\n\n");
}

int main(int argc, char **argv)
{
	int ret = 0;
	const char *format_str;
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

	printPRVHeader(ctx, prv);
	printPCFHeader(pcf);

	/* This two, have to be in this order, if not we remove the string
	 * syscall_entry_ before traversing the trace and the events don't
	 * get listed properly.
	 */
	iter_trace(ctx, prv);
	list_events(ctx, pcf);

end:
	bt_context_put(ctx);
	fflush(prv);
	fflush(pcf);
	fclose(prv);
	fclose(pcf);

	return 0;
}
