#include "types.h"
#include "getThreadInfo.h"

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

void getThreadInfo(struct bt_context *ctx, uint64_t *offset, uint32_t *ncpus,
    GHashTable *tid_info_ht, GHashTable *tid_prv_ht, GList **tid_prv_l,
    GHashTable *irq_name_ht, uint32_t *nsoftirqs, GHashTable *irq_prv_ht,
    GList **irq_prv_l)
{
  uint32_t ncpus_cmp = 0;
  gint tid;
  char name[16];
  char *irqname;

  struct bt_iter_pos begin_pos;
  struct bt_ctf_iter *iter;
  struct bt_ctf_event *event;
  int flags;
  int ret = 0;
  uint prvtid = 1;
  uint irqprv = 1;

  trace_times.first_stream_timestamp = 0;
  trace_times.last_stream_timestamp = 0;
  *offset = 0;

  const struct bt_definition *scope;

  begin_pos.type = BT_SEEK_BEGIN;
  iter = bt_ctf_iter_create(ctx, &begin_pos, NULL);
  bt_ctf_iter_add_callback(iter,
      g_quark_from_static_string("exit_syscall"), NULL, 0,
      handle_exit_syscall, NULL, NULL, NULL);

  while ((event = bt_ctf_iter_read_event_flags(iter, &flags)) != NULL)
  {
    scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
    ncpus_cmp = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "cpu_id"));
    if (ncpus_cmp > *ncpus)
    {
      *ncpus = ncpus_cmp;
    }

    /** Get Timestamps  and offset **/
    if (trace_times.first_stream_timestamp > bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_begin")) || trace_times.first_stream_timestamp == 0)
    {
      trace_times.first_stream_timestamp = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_begin"));
    }
    if (trace_times.last_stream_timestamp < bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_end")) || trace_times.last_stream_timestamp == 0)
    {
      trace_times.last_stream_timestamp = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "timestamp_end"));
    }

    if (*offset > bt_ctf_get_timestamp(event) || *offset == 0)
    {
      *offset = bt_ctf_get_timestamp(event);
    }

    /** Get thread names **/
    if (strstr(bt_ctf_event_name(event), "lttng_statedump_process_state") != NULL)
    {
      scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
      tid = bt_get_signed_int(bt_ctf_get_field(event, scope, "_tid"));

      strcpy(name, bt_ctf_get_char_array(bt_ctf_get_field(event, scope, "_name")));

      // Insert thread info into hash table
      if (g_hash_table_insert(tid_info_ht, GINT_TO_POINTER(tid), g_strdup(name)))
      {
        g_hash_table_insert(tid_prv_ht, GINT_TO_POINTER(tid), GINT_TO_POINTER(prvtid));
        *tid_prv_l = g_list_append(*tid_prv_l, GINT_TO_POINTER(tid));
        prvtid++;
      }
    }

    if (strstr(bt_ctf_event_name(event), "sched_switch") != NULL)
    {
      scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
      tid = bt_get_signed_int(bt_ctf_get_field(event, scope, "_next_tid"));
      strcpy(name, bt_ctf_get_char_array(bt_ctf_get_field(event, scope, "_next_comm")));
      if(g_hash_table_insert(tid_info_ht, GINT_TO_POINTER(tid), g_strdup(name)))
      {
        g_hash_table_insert(tid_prv_ht, GINT_TO_POINTER(tid), GINT_TO_POINTER(prvtid));
        *tid_prv_l = g_list_append(*tid_prv_l, GINT_TO_POINTER(tid));
        prvtid++;
      }
    }

    if (strcmp(bt_ctf_event_name(event), "softirq_entry") == 0)
    {
      scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
      tid = bt_get_unsigned_int(bt_ctf_get_field(event, scope, "_vec"));
      if (tid > *nsoftirqs) *nsoftirqs = tid;
    }

    if (strcmp(bt_ctf_event_name(event), "irq_handler_entry") == 0)
    {
      scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
      tid = bt_get_signed_int(bt_ctf_get_field(event, scope, "_irq"));
      irqname = (char *) malloc(sizeof(char *) * (strlen(bt_ctf_get_string(bt_ctf_get_field(event, scope, "_name"))) + 1 ));
      strcpy(irqname, bt_ctf_get_string(bt_ctf_get_field(event, scope, "_name")));
      if(g_hash_table_insert(irq_name_ht, GINT_TO_POINTER(tid), g_strdup(irqname)))
      {
        g_hash_table_insert(irq_prv_ht, GINT_TO_POINTER(tid), GINT_TO_POINTER(irqprv));
        *irq_prv_l = g_list_append(*irq_prv_l, GINT_TO_POINTER(tid));
        irqprv++;
      }
    }

    ret = bt_iter_next(bt_ctf_get_iter(iter));

    if (ret < 0)
      goto end_iter;
  }

end_iter:
  bt_ctf_iter_destroy(iter);
}
