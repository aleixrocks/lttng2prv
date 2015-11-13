#include "types.h"
#include "ctf2prv.h"

static char *opt_output;
const char *inputTrace;

int main(int argc, char **argv)
{
	int ret = 0;
	struct bt_context *ctx;
	int nresources;
	uint32_t nsoftirqs = 0;
	uint32_t ncpus = 0;
	uint64_t offset;

	FILE *prv, *pcf, *row;

	GHashTable *tid_info_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	GHashTable *tid_prv_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	GList *tid_prv_l = NULL;
	GHashTable *irq_name_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	GHashTable *irq_prv_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	GList *irq_prv_l = NULL;
	GHashTable *arg_types_ht = g_hash_table_new(g_str_hash, g_str_equal);

	ret = parse_options(argc, argv);
	if (ret < 0)
	{
		fprintf(stderr, "Error parsing options.\n\n");
		print_usage(stderr);
		exit(EXIT_FAILURE);
	}else if (ret > 0)
	{
		exit(EXIT_SUCCESS);
	}

	if (!opt_output)
	{
		opt_output = (char *)calloc(strlen("trace"), sizeof(char *));
		strcpy(opt_output, "trace");
	}
	strcat(opt_output, ".prv");
	prv = fopen(opt_output, "w");
	opt_output[strlen(opt_output) - 4] = 0;
	strcat(opt_output, ".pcf");
	pcf = fopen(opt_output, "w");
	opt_output[strlen(opt_output) - 4] = 0;
	strcat(opt_output, ".row");
	row = fopen(opt_output, "w");

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

	getThreadInfo(ctx, &offset, &ncpus, tid_info_ht, tid_prv_ht, &tid_prv_l, irq_name_ht, &nsoftirqs, irq_prv_ht, &irq_prv_l);
	// lttng starts cpu counting from 0, paraver from 1.
	ncpus = ncpus + 1;
	nresources = ncpus + nsoftirqs + g_hash_table_size(irq_name_ht);
	printPRVHeader(ctx, &offset, prv, tid_info_ht, nresources);
	printPCFHeader(pcf);
	printROW(row, tid_info_ht, tid_prv_l, irq_name_ht, irq_prv_l, ncpus, nsoftirqs);

	fillArgTypes(arg_types_ht);

	/* This two, have to be in this order, if not we remove the string
	 * syscall_entry_ before traversing the trace and the events don't
	 * get listed properly.
	 */
	iter_trace(ctx, &offset, prv, tid_info_ht, tid_prv_ht, irq_name_ht, irq_prv_ht, ncpus, nsoftirqs, arg_types_ht);
	list_events(ctx, pcf);

end:
	bt_context_put(ctx);

	g_hash_table_destroy(tid_info_ht);
	g_hash_table_destroy(tid_prv_ht);
	g_list_free(tid_prv_l);
	g_hash_table_destroy(irq_name_ht);
	g_hash_table_destroy(irq_prv_ht);
	g_list_free(irq_prv_l);
	g_hash_table_destroy(arg_types_ht);

	fflush(prv);
	fflush(pcf);
	fflush(row);
	fclose(prv);
	fclose(pcf);
	fclose(row);

	return 0;
}

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
					ret = -EINVAL;
				}
				break;
			case OPT_HELP:
				print_usage(stdout);
				ret = 1;
				goto end;
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

	if (pc)
	{
		poptFreeContext(pc);
	}

end:
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

// Iterates through all events of the trace
void iter_trace(struct bt_context *bt_ctx, uint64_t *offset, FILE *fp, GHashTable *tid_info_ht, GHashTable *tid_prv_ht, GHashTable *irq_name_ht, GHashTable *irq_prv_ht, const uint32_t ncpus, const uint32_t nsoftirqs, GHashTable *arg_types_ht)
{
	struct bt_ctf_iter *iter;
	struct bt_iter_pos begin_pos;
	struct bt_ctf_event *event;
	const struct bt_definition *scope;
	int ret = 0;
	int flags;
	uint64_t appl_id, task_id, thread_id, init_time, end_time, event_time; //,state;
	uint32_t cpu_id, irq_id;
	uint64_t event_type, event_value, offset_stream;
	char *event_name;
	uint32_t systemTID, prvTID, swapper;

	char fields[256];

	short int print = 0;

	begin_pos.type = BT_SEEK_BEGIN;
	iter = bt_ctf_iter_create(bt_ctx, &begin_pos, NULL);
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("exit_syscall"), NULL, 0,
			handle_exit_syscall, NULL, NULL, NULL);

	init_time = 0;
	end_time = 0;
	appl_id = 0;
	task_id = 1;
	thread_id = 1;

	swapper = GPOINTER_TO_INT(g_hash_table_lookup(tid_prv_ht, GINT_TO_POINTER(0)));

	while ((event = bt_ctf_iter_read_event_flags(iter, &flags)) != NULL)
	{
		print = 1;
		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
		cpu_id = bt_get_unsigned_int(bt_ctf_get_field(event, scope, "cpu_id"));

		event_name = (char *) malloc(sizeof(char *) * strlen(bt_ctf_event_name(event) + 1));
		strcpy(event_name, bt_ctf_event_name(event));

/**************************** State Records ***************************/

		if (strstr(event_name, "sched_switch") != NULL)
		{
			offset_stream = trace_times.first_stream_timestamp;
//			state = 3;
			end_time = bt_ctf_get_timestamp(event) - *offset - offset_stream;

			scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
			systemTID = bt_get_signed_int(bt_ctf_get_field(event, scope, "_prev_tid"));
			prvTID = GPOINTER_TO_INT(g_hash_table_lookup(tid_prv_ht, GINT_TO_POINTER(systemTID)));
			if (systemTID == 0)
			{
				prvTID = swapper;
			}
			appl_id = prvTID;

//			state = 2;
			scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
			systemTID = bt_get_signed_int(bt_ctf_get_field(event, scope, "_next_tid"));
			prvTID = GPOINTER_TO_INT(g_hash_table_lookup(tid_prv_ht, GINT_TO_POINTER(systemTID)));
			if (systemTID == 0)
			{
				prvTID = swapper;
			}
			appl_id = prvTID;

			init_time = end_time;
		}

		if (strstr(event_name, "sched_wakeup") != NULL)
		{
			offset_stream = trace_times.first_stream_timestamp;
//			state = 3;
			end_time = bt_ctf_get_timestamp(event) - *offset - offset_stream;

			scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
			systemTID = bt_get_signed_int(bt_ctf_get_field(event, scope, "_tid"));
			prvTID = GPOINTER_TO_INT(g_hash_table_lookup(tid_prv_ht, GINT_TO_POINTER(systemTID)));
			if (systemTID == 0)
			{
				prvTID = swapper;
			}
			appl_id = prvTID;

			init_time = end_time;
		}

		if (strcmp(event_name, "syscall_entry") == 0)
		{
			offset_stream = trace_times.first_stream_timestamp;
			end_time = bt_ctf_get_timestamp(event) - *offset - offset_stream;
//			state = 4; // SYSCALL

			appl_id = prvTID;

			init_time = end_time;
		}

		if (strcmp(event_name, "syscall_exit") == 0)
		{
			offset_stream = trace_times.first_stream_timestamp;
//			state = 2;
			end_time = bt_ctf_get_timestamp(event) - *offset - offset_stream;

			appl_id = prvTID;

			init_time = end_time;
		}

/**************************** /State Records **************************/

/**************************** Event Records ***************************/

		offset_stream = trace_times.first_stream_timestamp;

		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
		init_time = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_begin"));
		end_time = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_end")) - init_time;
		init_time = init_time - offset_stream;

		event_time = bt_ctf_get_timestamp(event) - *offset - offset_stream;

		scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_HEADER);
		event_value = bt_ctf_get_uint64(bt_ctf_get_enum_int(bt_ctf_get_field(event, scope, "id")));
		if (strstr(event_name, "syscall_entry_") != NULL)
		{
			event_type = 10000000;
//			state = 4;
		}else if (strstr(event_name, "syscall_exit_") != NULL)
		{
			event_type = 10000000;
			event_value = 0;
//			state = 2;
		} else if (strstr(event_name, "irq_handler_") != NULL)
		{
			event_type = 12000000;
			appl_id = 1;
			if (strcmp(event_name, "irq_handler_exit") == 0)
			{
				event_value = 0;
			}
			scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
			irq_id = bt_get_signed_int(bt_ctf_get_field(event, scope, "_irq"));
			cpu_id = ncpus + nsoftirqs + GPOINTER_TO_INT(g_hash_table_lookup(irq_prv_ht, GINT_TO_POINTER(irq_id))) - 1;
		}else if (strstr(event_name, "softirq_") != NULL)
		{
			event_type = 11000000;
			appl_id = 1;
			if (strcmp(event_name, "softirq_raise") == 0)
			{
				print = 0;
			}else if (strcmp(event_name, "softirq_exit") == 0)
			{
				event_value = 0;
			}
			scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
			cpu_id = ncpus - 1 + bt_get_unsigned_int(bt_ctf_get_field(event, scope, "_vec"));
		}else
		{
			event_type = 19000000;
			if ((strcmp(event_name, "sched_process_exit") == 0) ||
					(strcmp(event_name, "hrtimer_expire_exit") == 0) ||
					(strcmp(event_name, "timer_expire_exit") == 0) ||
					(strcmp(event_name, "kvm_userspace_exit") == 0) ||
					(strcmp(event_name, "kvm_exit") == 0) ||
					(strcmp(event_name, "ext4_ind_map_blocks_exit") == 0) ||
					(strcmp(event_name, "ext4_ext_map_blocks_exit") == 0) ||
					(strcmp(event_name, "ext4_truncate_exit") == 0) ||
					(strcmp(event_name, "ext4_unlink_exit") == 0) ||
					(strcmp(event_name, "ext4_fallocate_exit") == 0) ||
					(strcmp(event_name, "ext4_direct_IO_exit") == 0) ||
					(strcmp(event_name, "ext4_sync_file_exit") == 0))
			{
				event_value = 0;
			}
		}
		
/*****		 ID for value == 65536 in extended metadata		*****/
		if (event_value == 65535)
		{
			event_value = bt_ctf_get_uint64(bt_ctf_get_struct_field_index(bt_ctf_get_field(event, scope, "v"), 0));
		}

		// Get Call Arguments
		fields[0] = '\0';
		getArgValue(event, arg_types_ht, &fields[0]);

		if (print != 0)
		{
			fprintf(fp, "2:%u:%lu:%lu:%lu:%lu:%lu:%lu%s\n", cpu_id + 1, appl_id, task_id, thread_id, event_time, event_type, event_value, fields);
		}
		free(event_name);


/*************************** /Event Records ***************************/

		if (flags) 
		{
			fprintf(stderr, "LOST : %" PRIu64 "\n", bt_ctf_get_lost_events_count(iter));
		}

		ret = bt_iter_next(bt_ctf_get_iter(iter));

		if (ret < 0)
			goto end_iter;
	}

end_iter:
	bt_ctf_iter_destroy(iter);

}
