#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE 700

#include "types.h"
#include "lttng2prv.h"
#include "fillArgTypes.h"
#include "listEvents.h"

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

static int bt_context_add_traces_recursive(struct bt_context *_ctx,
    const char *_path, const char *_format_str,
    void (*packet_seek)(struct bt_stream_pos *pos, size_t offset, int whence));

static void iter_trace(struct bt_context *_bt_ctx, uint64_t *_offset, FILE *_fp,
    GHashTable *_tid_info_ht, GHashTable *_tid_prv_ht, GHashTable *_irq_name_ht,
    GHashTable *_irq_prv_ht, const uint32_t _ncpus, const uint32_t _nsoftirqs,
    GHashTable *_arg_types_ht, GHashTable *_lost_events_ht);

static void key_destroy_func(gpointer _key);

static char *opt_output;
const char *inputTrace;
static bool print_timestamps = false;
bool verbose = false;
unsigned int id_size = 32;

int
main(int argc, char **argv)
{
        int ret = 0;
        struct bt_context *ctx;
        int nresources;
        uint32_t nsoftirqs = 0;
        uint32_t ncpus = 0;
        size_t trace_offset;
        char *ofilename, *metadatafn;

        FILE *prv, *pcf, *row, *metadatafp;

        GHashTable *tid_info_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, key_destroy_func);
        GHashTable *tid_prv_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
        GList *tid_prv_l = NULL;
        GHashTable *irq_name_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, key_destroy_func);
        GHashTable *irq_prv_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
        GList *irq_prv_l = NULL;
        GHashTable *arg_types_ht = g_hash_table_new_full(
            g_str_hash, g_str_equal, (GDestroyNotify) key_destroy_func, NULL);
        GHashTable *lost_events_ht = g_hash_table_new(g_direct_hash, g_direct_equal);

        ret = parse_options(argc, argv);
        if (ret < 0) {
                fprintf(stderr, "Error parsing options.\n");
                exit(EXIT_FAILURE);
        } else if (ret > 0) {
                exit(EXIT_SUCCESS);
        }

        if (!opt_output) {
                char *it = calloc(strlen(inputTrace) + 1, sizeof(char *));
                strncpy(it, inputTrace, strlen(inputTrace));
                opt_output = (char *)calloc(strlen(basename(it)) + 1,
                    sizeof(char *));
                strncpy(opt_output, basename(it), strlen(basename(it)));
        }
        ofilename = (char *)calloc(strlen(opt_output) + 5, sizeof(char *));
        strncpy(ofilename, opt_output, strlen(opt_output) + 1);

        metadatafn = (char *)calloc(strlen(inputTrace) + 9, sizeof(char *));
        strncat(metadatafn, inputTrace, strlen(inputTrace));
        strncat(metadatafn, "/metadata", strlen("/metadata"));

        char *tmp = malloc(512 * sizeof(char *));
        if (!(metadatafp = fopen(metadatafn, "r"))) {
                fprintf(stderr, "[error] Couldn't open metadata file.\n");
                goto endmeta;
        }

        while (fgets(tmp, 512, metadatafp) != NULL) {
                if (strstr(tmp, "event.header := struct event_header_large")) {
                        debug("Extended header.\n");
                        id_size = 65536;
                }
                if (strstr(tmp, "offset = ")) {
                        strtok(tmp, "=");
                        trace_offset = strtoul(strtok(NULL, "="), NULL, 10);
                        debug("Trace offset = %lu\n", trace_offset);
                }
        }
        fclose(metadatafp);
        free(tmp);
        free(metadatafn);

        strcat(ofilename, ".prv");
        if (!(prv = fopen(ofilename, "w"))) {
                fprintf(stderr,
                    "[error] Couldn't open trace file for writing.\n");
                goto endprv;
        }

        ofilename[strlen(opt_output)] = 0;
        strcat(ofilename, ".pcf");
        if (!(pcf = fopen(ofilename, "w"))) {
                fprintf(stderr,
                    "[error] Couldn't open configuration file for writing.\n");
                goto endpcf;
        }

        ofilename[strlen(opt_output)] = 0;
        strcat(ofilename, ".row");
        if (!(row = fopen(ofilename, "w"))) {
                fprintf(stderr,
                    "[error] Couldn't open names file for writing.\n");
                goto endrow;
        }

        ctx = bt_context_create();
        if (!ctx) {
                fprintf(stderr, "Couldn't create context.\n");
                goto end;
        }

        ret = bt_context_add_traces_recursive(ctx, inputTrace, "ctf", NULL);
        if (ret < 0) {
                fprintf(stderr,
                    "Couldn't open trace \"%s\" for reading.\n", inputTrace);
                goto end;
        }

        getThreadInfo(ctx, &ncpus, tid_info_ht, tid_prv_ht,
            &tid_prv_l, irq_name_ht, &nsoftirqs, irq_prv_ht, &irq_prv_l,
            lost_events_ht);
        //debug("offset = %zu\n", offset);
        /* lttng starts cpu counting from 0, paraver from 1 */
        ncpus = ncpus + 1;
        nresources = ncpus + nsoftirqs + g_hash_table_size(irq_name_ht);
        printPRVHeader(ctx, prv, tid_info_ht, nresources);
        printPCFHeader(pcf);
        printROW(row, tid_info_ht, tid_prv_l, irq_name_ht, irq_prv_l,
            ncpus, nsoftirqs);

        fillArgTypes(arg_types_ht);

        /* This two, have to be in this order, if not we remove the string
         * syscall_entry_ before traversing the trace and the events don't
         * get listed properly.
        */
        iter_trace(ctx, &trace_offset, prv, tid_info_ht, tid_prv_ht, irq_name_ht,
            irq_prv_ht, ncpus, nsoftirqs, arg_types_ht, lost_events_ht);
        listEvents(ctx, pcf);

end:
        bt_context_put(ctx);

        g_hash_table_destroy(tid_info_ht);
        g_hash_table_destroy(tid_prv_ht);
        g_list_free(tid_prv_l);
        g_hash_table_destroy(irq_name_ht);
        g_hash_table_destroy(irq_prv_ht);
        g_list_free(irq_prv_l);
        g_hash_table_destroy(arg_types_ht);

        free(ofilename);

endrow:
        fflush(row);
        fclose(row);

endpcf:
        fflush(pcf);
        fclose(pcf);

endprv:
        fflush(prv);
        fclose(prv);

endmeta:
        return 0;
}

static void
key_destroy_func(gpointer key)
{
        g_free(key);
}

static int
parse_options(int argc, char **argv)
{
        poptContext pc;
        int opt, ret = 0;

        pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 0);
        poptReadDefaultConfig(pc, 0);
        poptSetOtherOptionHelp(pc, "[OPTIONS...] <lttng_trace>");

        if (argc == 1) {
                poptPrintHelp(pc, stderr, 0);
                return 1;
        }

        while ((opt = poptGetNextOpt(pc)) != -1) {
                switch (opt) {
                case OPT_OUTPUT:
                        opt_output = (char *) poptGetOptArg(pc);
                        if (!opt_output) {
                                fprintf(stderr, "Wrong file name\n");
                                ret = -EINVAL;
                        }
                        break;
                case OPT_TIMESTAMPS:
                        print_timestamps = true;
                        break;
                case OPT_VERBOSE:
                        verbose = true;
                        break;
                default:
                        poptPrintHelp(pc, stderr, 0);
                        ret = -EINVAL;
                        break;
                }
        }

        inputTrace = poptGetArg(pc);
        if (inputTrace == NULL) {
                ret = -EINVAL;
        }

        if (pc) {
                poptFreeContext(pc);
        }

        return ret;
}

static GPtrArray *traversed_paths = 0;

static int
traverse_trace_dir(const char *fpath, const struct stat *sb, int tflag,
    struct FTW *ftwbuf)
{
        int dirfd, metafd;
        int closeret;

        if (tflag != FTW_D) {
                return 0;
        }

        dirfd = open(fpath, 0);
        if (dirfd < 0) {
                fprintf(stderr, "[error] [Context] Unable to open trace "
                    "directory file desciptor.\n");
                return 0;
        }
        metafd = openat(dirfd, "metadata", O_RDONLY);
        if (metafd < 0) {
                closeret = close(dirfd);
                if (closeret < 0) {
                        perror("close");
                        return -1;
                }
                return 0;
        } else {
                closeret = close(metafd);
                if (closeret < 0) {
                        perror("close");
                        return -1;
                }
                closeret = close(dirfd);
                if (closeret < 0) {
                        perror("close");
                        return -1;
                }

                if (traversed_paths == NULL) {
                        fprintf(stderr,
                            "[error] [Context] Invalid open path array.\n");
                        return -1;
                }
                g_ptr_array_add(traversed_paths, g_string_new(fpath));
        }

        return 0;
}

static int
bt_context_add_traces_recursive(struct bt_context *ctx,
    const char *path, const char *format_str,
    void (*packet_seek)(struct bt_stream_pos *pos, size_t offset, int whence))
{
        GArray *trace_ids;
        int ret = 0;
        int i;

        traversed_paths = g_ptr_array_new();
        trace_ids = g_array_new(FALSE, TRUE, sizeof(int));

        ret = nftw(path, traverse_trace_dir, 10, 0);

        if (ret >= 0) {
                for (i = 0; i < traversed_paths->len; i++) {
                        GString *trace_path =
                            g_ptr_array_index(traversed_paths, i);
                        int trace_id = bt_context_add_trace(
                            ctx,
                            trace_path->str,
                            format_str,
                            packet_seek,
                            NULL,
                            NULL);
                        if (trace_id < 0) {
                                fprintf(stderr,
                                    "[warning] [Context] cannot open trace \"%s\""
                                    "from %s for reading.\n",
                                    trace_path->str, path);
                                ret = 1;
                        } else {
                                debug("Adding trace # : %d\n", trace_id);
                                g_array_append_val(trace_ids, trace_id);
                        }
                        g_string_free(trace_path, TRUE);
                }
        }
        g_ptr_array_free(traversed_paths, TRUE);
        traversed_paths = NULL;

        if (trace_ids->len == 0) {
                fprintf(stderr, "[error] Cannot open any trace for reading.\n\n");
                ret = -ENOENT;
        }
        g_array_free(trace_ids, TRUE);
        return ret;
}

/*
 * Iterates through all events of the trace
 */
static void
iter_trace(struct bt_context *bt_ctx, uint64_t *trace_offset, FILE *fp,
    GHashTable *tid_info_ht, GHashTable *tid_prv_ht, GHashTable *irq_name_ht,
    GHashTable *irq_prv_ht, const uint32_t ncpus, const uint32_t nsoftirqs,
    GHashTable *arg_types_ht, GHashTable *lost_events_ht)
{
        struct bt_ctf_iter *iter;
        struct bt_iter_pos begin_pos;
        struct bt_ctf_event *event;
        const struct bt_definition *scope;
        int ret = 0;
        int flags;
        unsigned int nresources = ncpus + nsoftirqs +
            g_hash_table_size(irq_name_ht);
        /* independent appl_id for each resource (CPU or IRQ) */
        uint64_t appl_id[nresources];//, prev_appl_id = 0;
        uint64_t task_id, thread_id, event_time;//, prev_event_time = 0;
        uint32_t cpu_id, irq_id;//, prev_cpu_id = 0;
        uint64_t event_type, event_value, offset_stream;//, begin_time, end_time;
        unsigned int state;
        uint64_t prev_state;
        char *event_name;
        uint32_t systemTID, prvTID, swapper;

        char fields[256];

        short int print = 0;
        short int print_state = 0;

        void *lostEvents = NULL;
        size_t lost_ini, lost_fi;

        begin_pos.type = BT_SEEK_BEGIN;
        iter = bt_ctf_iter_create(bt_ctx, &begin_pos, NULL);
        bt_ctf_iter_add_callback(iter,
            g_quark_from_static_string("exit_syscall"), NULL, 0,
            handle_exit_syscall, NULL, NULL, NULL);

        task_id = 1;
        thread_id = 1;

        for (int i = 0; i < nresources; i++) {
                appl_id[i] = 0;
        }

        swapper = GPOINTER_TO_INT(g_hash_table_lookup(tid_prv_ht,
            GINT_TO_POINTER(0)));

        while ((event = bt_ctf_iter_read_event_flags(iter, &flags)) != NULL) {
                print = 1;
                print_state = 1;
                scope = bt_ctf_get_top_level_scope(event,
                    BT_STREAM_PACKET_CONTEXT);
                cpu_id = bt_get_unsigned_int(bt_ctf_get_field(event, scope,
                    "cpu_id"));

                event_name = (char *) malloc(sizeof(char *) *
                    strlen(bt_ctf_event_name(event) + 1));
                strcpy(event_name, bt_ctf_event_name(event));

                /* State Records */

                if (strstr(event_name, "sched_switch") != NULL) {
                        offset_stream = trace_times.first_stream_timestamp;

                        scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
                        systemTID = bt_get_signed_int(
                            bt_ctf_get_field(event, scope, "_next_tid"));
                        prvTID = GPOINTER_TO_INT(
                            g_hash_table_lookup(
                                tid_prv_ht, GINT_TO_POINTER(systemTID)));

                        if (systemTID == 0) {
                                prvTID = swapper;
                        }
                        appl_id[cpu_id] = prvTID;
                }

                if (strcmp(event_name, "syscall_entry") == 0) {
                        offset_stream = trace_times.first_stream_timestamp;
                        //      state = 4; // SYSCALL

                        //appl_id = prvTID;
                }

                if (strcmp(event_name, "syscall_exit") == 0) {
                        offset_stream = trace_times.first_stream_timestamp;
                        //      state = 2;

                        //appl_id = prvTID;
                }

                /* /State Records */

                /* Event Records */

                offset_stream = trace_times.first_stream_timestamp;

                // scope = bt_ctf_get_top_level_scope(event,
                //    BT_STREAM_PACKET_CONTEXT);

                event_time = bt_ctf_get_timestamp(event) - offset_stream;

                scope = bt_ctf_get_top_level_scope(event,
                    BT_STREAM_EVENT_HEADER);

                /* Add 1 to the event_value to reserve 0 for exit */
                event_value = bt_ctf_get_uint64(
                    bt_ctf_get_enum_int(
                        bt_ctf_get_field(event, scope, "id"))) + 1;
                if (strstr(event_name, "syscall_entry_") != NULL) {
                        event_type = 10000000;
                        state = STATE_SYSCALL;
                        if (strstr(event_name, "syscall_entry_exit") != NULL) {
                                event_value = 0;
                        }
                } else if (strstr(event_name, "syscall_exit_") != NULL) {
                        event_type = 10000000;
                        event_value = 0;
                        state = STATE_USERMODE;
                /*
                 * For softirq and irq_handler types we manually specify the
                 * event_value IDs instead of using the one provided by lttng.
                 * This way we always use the same values for these events.
                 */
                } else if (strstr(event_name, "irq_handler_") != NULL) {
                        event_type = 10200000;
                        event_value = 1;
                        state = STATE_IRQ;
                        //appl_id = 1;
                        if (strstr(event_name, "irq_handler_exit") != NULL) {
                                event_value = 0;
                                state = STATE_USERMODE;
                        }
                        scope = bt_ctf_get_top_level_scope(event,
                            BT_EVENT_FIELDS);
                        irq_id = bt_get_signed_int(
                            bt_ctf_get_field(event, scope, "_irq"));
                        irq_id = ncpus + nsoftirqs +
                                GPOINTER_TO_INT(g_hash_table_lookup(
                                        irq_prv_ht, GINT_TO_POINTER(irq_id))) - 1;
                        /* assign the same thread_id of the calling process
                         * to the irq position
                         */
                        appl_id[irq_id] = appl_id[cpu_id];
                        /* we need cpu_id to be the identifier of the irq
                         * to properly print the prv line
                         */
                        cpu_id = irq_id;
                } else if (strstr(event_name, "softirq_") != NULL) {
                        event_type = 10100000;
                        state = STATE_SOFTIRQ;
                        event_value = 1;
                        //appl_id = 1;
                        if (strstr(event_name, "softirq_raise") != NULL) {
                                print = 0;
                                event_value = 2;
                        } else if (strstr(event_name, "softirq_exit") != NULL) {
                                event_value = 0;
                                state = STATE_USERMODE;
                        }
                        scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
                        irq_id = ncpus - 1 + bt_get_unsigned_int(
                            bt_ctf_get_field(event, scope, "_vec"));
                        /* Assign the same thread_id of the calling process
                         * to the irq position
                         */
                        appl_id[irq_id] = appl_id[cpu_id];
                        /* We need cpu_id to be the identifier of the irq
                         * to properly print the prv line
                         */
                        cpu_id = irq_id;
                } else if ((strstr(event_name, "netif_") != NULL) ||
                            (strstr(event_name, "net_dev_") != NULL)) {
                        event_type = 10300000;
                        state = STATE_NETWORK;
                        print_state = 0;
                } else if (strcmp(event_name, "sched_switch") == 0) {
                        event_type = 10900000;
                        scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
                        systemTID = bt_get_signed_int(
                        bt_ctf_get_field(event, scope, "_prev_tid"));
                        prvTID = GPOINTER_TO_INT(
                            g_hash_table_lookup(
                                tid_prv_ht, GINT_TO_POINTER(systemTID)));
                        if (systemTID == 0) {
                                prvTID = swapper;
                        }

                        prev_state = bt_get_signed_int(
                            bt_ctf_get_field(event, scope, "_prev_state"));
                        if (prev_state == 0) {
                                state = STATE_WAIT_CPU;
                        } else {
                                state = STATE_WAIT_BLOCK;
                        }

                        fprintf(fp, "2:%u:%u:%lu:%lu:%lu:20000000:%u\n",
                            cpu_id + 1, prvTID, task_id, thread_id,
                            event_time, state);

                        state = STATE_USERMODE;
                } else if (strcmp(event_name, "sched_wakeup") == 0) {
                        event_type = 10900000;
                        state = STATE_WAIT_CPU;
                        scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
                        systemTID = bt_get_signed_int(
                            bt_ctf_get_field(event, scope, "_tid"));
                        prvTID = GPOINTER_TO_INT(
                        g_hash_table_lookup(
                            tid_prv_ht, GINT_TO_POINTER(systemTID)));
                        if (systemTID == 0) {
                                prvTID = swapper;
                        }
                        fprintf(fp, "2:%u:%u:%lu:%lu:%lu:20000000:%d:20000000:%u\n",
                            cpu_id + 1, prvTID, task_id,
                            thread_id, event_time, STATE_USERMODE, state);
                        state = STATE_USERMODE;
                        print_state = 0;
                } else if (strcmp(event_name, "sched_process_fork") == 0) {
                        event_type = 10900000;
                        state = STATE_WAIT_CPU;
                        scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
                        systemTID = bt_get_signed_int(
                            bt_ctf_get_field(event, scope, "_child_tid"));
                        prvTID = GPOINTER_TO_INT(
                        g_hash_table_lookup(
                            tid_prv_ht, GINT_TO_POINTER(systemTID)));
                        if (systemTID == 0) {
                                prvTID = swapper;
                        }
                        fprintf(fp, "2:%u:%u:%lu:%lu:%lu:20000000:%u\n",
                            cpu_id + 1, prvTID, task_id,
                            thread_id, event_time, state);
                        state = STATE_USERMODE;
                        print_state = 0;
                } else {
                        event_type = 10900000;
                        state = STATE_USERMODE;
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
                            (strcmp(event_name, "ext4_sync_file_exit") == 0)) {
//                        if (strstr(event_name, "_exit") != 0) {
                                event_value = 0;
                                state = STATE_USERMODE;
                        }
                        print_state = 0;
                }

                /* ID for value == 65536 in extended metadata */
                if (event_value == id_size) {
//                if (event_value == 65536) {
                        // Add 1 to the new event_value to reserve 0 for exit
                        event_value = bt_ctf_get_uint64(
                            bt_ctf_get_struct_field_index(
                                bt_ctf_get_field(event, scope, "v"), 0)) + 1;
                }

                /* Get Call Arguments */
                fields[0] = '\0';
                getArgValue(event, event_type, arg_types_ht, &fields[0]);

                /*
                 * Prints lost events if found assigned to the same application
                 * and CPU as the last recorded event.
                 */
                if ((lostEvents = g_hash_table_lookup(lost_events_ht, GINT_TO_POINTER(bt_ctf_get_timestamp(event))))) {
                        /* Test */
                        scope = bt_ctf_get_top_level_scope(event,
                            BT_STREAM_PACKET_CONTEXT);
                        /* Is the same as event_time
                        lost_ini = bt_ctf_get_uint64(
                            bt_ctf_get_field(event, scope, "timestamp_begin")) + 
                            *trace_offset - trace_times.first_stream_timestamp;
                        */
                        lost_ini = event_time;
                        lost_fi = bt_ctf_get_uint64(
                            bt_ctf_get_field(event, scope, "timestamp_end")) +
                            *trace_offset - trace_times.first_stream_timestamp;

                        fprintf(fp,
                            "2:%u:%lu:1:1:%" PRIu64 ":99999999:%d\n",
                            cpu_id + 1,
                            appl_id[cpu_id],
                            lost_ini,
                            GPOINTER_TO_INT(lostEvents));

                        fprintf(fp,
                            "2:%u:%lu:1:1:%" PRIu64 ":99999999:%d\n",
                            cpu_id + 1,
                            appl_id[cpu_id],
                            lost_fi,
                            0);

                        /* Orig
                        fprintf(fp, "2:%u:%lu:1:1:%lu:99999999:%d\n",
                            prev_cpu_id + 1, prev_appl_id,
                            prev_event_time, GPOINTER_TO_INT(lostEvents));
                        fprintf(fp, "2:%u:%lu:1:1:%lu:99999999:0\n",
                            prev_cpu_id + 1, prev_appl_id, event_time);
                        */

                        /* Use tasks instead of applications */
                        /*
                        fprintf(fp, "2:%u:1:%lu:1:%lu:99999999:%d\n",
                            prev_cpu_id + 1, prev_appl_id,
                            prev_event_time, GPOINTER_TO_INT(lostEvents));
                        fprintf(fp, "2:%u:1:%lu:1:%lu:99999999:0\n",
                            prev_cpu_id + 1, prev_appl_id, event_time);
                        */
                }

                /* print only if we know the appl_id of the event */
                if ((print != 0) && (appl_id[cpu_id] != 0)) {
                        if (print_state == 1) {
                                fprintf(fp, "2:%u:%lu:%lu:%lu:%lu:20000000:%u:%lu:%lu%s\n", 
                                    cpu_id + 1, appl_id[cpu_id], task_id,
                                    thread_id, event_time, state, event_type,
                                    event_value, fields);
                        } else {
                                fprintf(fp, 
                                    "2:%u:%lu:%lu:%lu:%lu:%lu:%lu%s\n", 
                                    cpu_id + 1, appl_id[cpu_id], task_id,
                                    thread_id, event_time, event_type,
                                    event_value, fields);
                        }
                        /* Use tasks instead of applications */
                        /*
                        if (print_state == 1) {
                        fprintf(fp, 
                            "2:%u:%lu:%lu:%lu:%lu:20000000:%u:%lu:%lu%s\n", 
                            cpu_id + 1, task_id, appl_id[cpu_id],
                            thread_id, event_time, state, event_type,
                            event_value, fields);
                        } else {
                                fprintf(fp, 
                                    "2:%u:%lu:%lu:%lu:%lu:%lu:%lu%s\n", 
                                    cpu_id + 1, task_id, appl_id[cpu_id],
                                    thread_id, event_time, event_type,
                                    event_value, fields);
                        }
                        */

                        if (event_type == 10300000) {
                                /* print exit from network call after 1ns */
                                /* Use tasks instead of applications
                                fprintf(fp, "2:%u:%lu:%lu:%lu:%lu:20000000:0:%lu:%d\n",
                                cpu_id + 1, appl_id[cpu_id], task_id, thread_id,
                                    event_time + 1, event_type, 0);
                                */
                                fprintf(fp,
                                    "2:%u:%lu:%lu:%lu:%lu:%lu:%d\n",
                                    cpu_id + 1, appl_id[cpu_id], task_id,
                                    thread_id, event_time + 1, event_type, 0);
                        }
                }
                //prev_event_time = event_time;
                //prev_cpu_id = cpu_id;
                //prev_appl_id = appl_id[cpu_id];
                free(event_name);


                /* /Event Records */

                if (flags) {
                        fprintf(stderr, "LOST : %" PRIu64 "\n",
                            bt_ctf_get_lost_events_count(iter));
                }

                ret = bt_iter_next(bt_ctf_get_iter(iter));

                if (ret < 0)
                        goto end_iter;
        }

end_iter:
        bt_ctf_iter_destroy(iter);

        if (print_timestamps) {
                // fprintf(stdout, ...) prints unwanted characters
                printf("LTTNG2PRV_INI=%lu\n",
                    (trace_times.first_stream_timestamp) / 1000000000);
                printf("LTTNG2PRV_FIN=%lu\n",
                    (trace_times.last_stream_timestamp) / 1000000000);
        }
}

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=8 shiftwidth=8 expandtab cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */
