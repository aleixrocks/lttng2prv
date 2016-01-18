#include "types.h"
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <inttypes.h>
#include <stdlib.h>
#include <babeltrace/ctf/events.h>

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

void printPRVHeader(struct bt_context *ctx, uint64_t *offset, FILE *fp,
    GHashTable *tid_info_ht, int nresources)
{
  *offset -= trace_times.first_stream_timestamp;

  time_t now = time(0);
  struct tm *local = localtime(&now);
  uint64_t ftime = trace_times.last_stream_timestamp - trace_times.first_stream_timestamp;

  char day[3], mon[3], hour[3], min[3];
  sprintf(day, "%.2d", local->tm_mday);
  sprintf(mon, "%.2d", local->tm_mon + 1);
  sprintf(hour, "%.2d", local->tm_hour);
  sprintf(min, "%.2d", local->tm_min);

  fprintf(fp, "#Paraver (%s/%s/%d at %s:%s):%" PRIu64 "_ns:1(%d):%d:",
      day,
      mon,
      local->tm_year + 1900,
      hour,
      min,
      ftime,
      nresources,
      g_hash_table_size(tid_info_ht) // nAppl
  );

  GHashTableIter ht_iter;
  gpointer key, value;
  g_hash_table_iter_init(&ht_iter, tid_info_ht);

  while (g_hash_table_iter_next(&ht_iter, &key, &value))
  {
    fprintf(fp, "1(1:1),");
  }
  // Remove last colon
  fseek(fp, -1, SEEK_CUR);
  fprintf(fp, "\n");
}

void printROW(FILE *fp, GHashTable *tid_info_ht, GList *tid_prv_l,
    GHashTable *irq_name_ht, GList *irq_prv_l, const uint32_t ncpus,
    const uint32_t nsoftirqs)
{
  gpointer value;
  int rcount = 0;

  fprintf(fp, "LEVEL CPU SIZE %d\n", ncpus + nsoftirqs + g_hash_table_size(irq_name_ht));
  while (rcount < ncpus)
  {
    fprintf(fp, "CPU %d\n", rcount + 1);
    rcount++;
  }

  rcount = 0;
  while (rcount < nsoftirqs)
  {
    fprintf(fp, "SOFTIRQ %d\n", rcount + 1);
    rcount++;
  }

  while (irq_prv_l != NULL)
  {
    value = g_hash_table_lookup(irq_name_ht, irq_prv_l->data);
    fprintf(fp, "IRQ %d %s\n", GPOINTER_TO_INT(irq_prv_l->data), (const char *)value);
    irq_prv_l = irq_prv_l->next;  
  }
  fprintf(fp, "\n\n");

  fprintf(fp, "LEVEL APPL SIZE %d\n", g_hash_table_size(tid_info_ht));
  while (tid_prv_l != NULL)
  {
    value = g_hash_table_lookup(tid_info_ht, tid_prv_l->data);
    fprintf(fp, "%s\n", (const char *)value);
    tid_prv_l = tid_prv_l->next;
  }
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
      "0\t\tIDLE\n"
      "1\t\tSYSCALL\n"
      "2\t\tUSERMODE\n"
      "3\t\tSOFT_IRQ\n"
      "4\t\tIRQ\n\n\n");

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

// Classifies and prints events found in the ctf tracefile
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
  struct Events *softirqs_root;
  struct Events *softirqs;
  struct Events *irqhandler_root;
  struct Events *irqhandler;
  struct Events *netcalls_root;
  struct Events *netcalls;

  syscalls_root = (struct Events *) malloc(sizeof(struct Events));
  syscalls_root->next = NULL;
  syscalls = syscalls_root;

  kerncalls_root = (struct Events *) malloc(sizeof(struct Events));
  kerncalls_root->next = NULL;
  kerncalls = kerncalls_root;

  softirqs_root = (struct Events *) malloc(sizeof(struct Events));
  softirqs_root->next = NULL;
  softirqs = softirqs_root;

  irqhandler_root = (struct Events *) malloc(sizeof(struct Events));
  irqhandler_root->next = NULL;
  irqhandler = irqhandler_root;

  netcalls_root = (struct Events *) malloc(sizeof(struct Events));
  netcalls_root->next = NULL;
  netcalls = netcalls_root;

  bt_ctf_get_event_decl_list(0, bt_ctx, &list, &cnt);
  for (i = 0; i < cnt; i++)
  {
    // Add 1 to the event_id to reserve 0 for exit
    event_id = bt_ctf_get_decl_event_id(list[i]) + 1;
    event_name = strndup(bt_ctf_get_decl_event_name(list[i]), strlen(bt_ctf_get_decl_event_name(list[i])));

    if ((strstr(event_name, "syscall_entry") != NULL) && (strstr(event_name, "syscall_entry_exit") == NULL))
    {
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
    } else if ((strstr(event_name, "softirq_raise") != NULL) || (strstr(event_name, "softirq_entry") != NULL))
    {
      softirqs->id = event_id;
      rmsubstr(event_name, "_entry");
      softirqs->name = (char *) malloc(strlen(event_name) + 1);
      strncpy(softirqs->name, event_name, strlen(event_name) + 1);
      softirqs->next = (struct Events*) malloc(sizeof(struct Events));
      softirqs = softirqs->next;
      softirqs->next = NULL;
    } else if (strstr(event_name, "irq_handler_entry") != NULL)
    {
      irqhandler->id = event_id;
      rmsubstr(event_name, "_entry");
      irqhandler->name = (char *) malloc(strlen(event_name) + 1);
      strncpy(irqhandler->name, event_name, strlen(event_name) + 1);
      irqhandler->next = (struct Events*) malloc(sizeof(struct Events));
      irqhandler = irqhandler->next;
      irqhandler->next = NULL;
    } else if ((strstr(event_name, "netif_") != NULL) || (strstr(event_name, "net_dev_") != NULL))
    {
      netcalls->id = event_id;
      netcalls->name = (char *) malloc(strlen(event_name) + 1);
      strncpy(netcalls->name, event_name, strlen(event_name) + 1);
      netcalls->next = (struct Events*) malloc(sizeof(struct Events));
      netcalls = netcalls->next;
      netcalls->next = NULL;
    } else if ((strstr(event_name, "syscall_exit") == NULL) && (strstr(event_name, "softirq_exit") == NULL) && (strstr(event_name, "irq_handler_exit") == NULL) && (strstr(event_name, "syscall_entry_exit") == NULL))
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
      "0\t10000000\tSystem Call\n"
      "VALUES\n");

  syscalls = syscalls_root;
  while(syscalls->next != NULL)
  {
    fprintf(fp, "%" PRIu64 "\t%s\n", syscalls->id, syscalls->name);
    syscalls = syscalls->next;
  }
  fprintf(fp, "0\texit\n\n\n");

  fprintf(fp, "EVENT_TYPE\n"
      "0\t11000000\tSOFTIRQ\n"
      "VALUES\n");

  softirqs = softirqs_root;
  while(softirqs->next != NULL)
  {
    fprintf(fp, "%" PRIu64 "\t%s\n", softirqs->id, softirqs->name);
    softirqs = softirqs->next;
  }
  fprintf(fp, "0\texit\n\n\n");

  fprintf(fp, "EVENT_TYPE\n"
      "0\t12000000\tIRQ HANDLER\n"
      "VALUES\n");

  irqhandler = irqhandler_root;
  while(irqhandler->next != NULL)
  {
    fprintf(fp, "%" PRIu64 "\t%s\n", irqhandler->id, irqhandler->name);
    irqhandler = irqhandler->next;
  }
  fprintf(fp, "0\texit\n\n\n");

  fprintf(fp, "EVENT_TYPE\n"
      "0\t13000000\tNETWORK CALLS\n"
      "VALUES\n");

  netcalls = netcalls_root;
  while(netcalls->next != NULL)
  {
    fprintf(fp, "%" PRIu64 "\t%s\n", netcalls->id, netcalls->name);
    netcalls = netcalls->next;
  }
  fprintf(fp, "0\texit\n\n\n");

  fprintf(fp, "EVENT_TYPE\n"
      "0\t19000000\tOthers\n"
      "VALUES\n");

  kerncalls = kerncalls_root;
  while(kerncalls->next != NULL)
  {
    fprintf(fp, "%" PRIu64 "\t%s\n", kerncalls->id, kerncalls->name);
    kerncalls = kerncalls->next;
  }
  fprintf(fp, "0\texit\n\n\n");

  fprintf(fp, "EVENT_TYPE\n");
  fprintf(fp, "0\t10000001\tSYSCALL_RET\n");
  fprintf(fp, "0\t12000001\tIRQ_RET\n");
  fprintf(fp, "0\t19000001\tOTHERS_RET\n");
  fprintf(fp, "0\t10000002\tSYSCALL_FD\n");
  fprintf(fp, "0\t10000003\tSYSCALL_SIZE\n");
  fprintf(fp, "0\t19000003\tOTHERS_SIZE\n");
  fprintf(fp, "0\t10000004\tSYSCALL_CMD\n");
  fprintf(fp, "0\t10000005\tSYSCALL_ARG\n");
  fprintf(fp, "0\t10000006\tSYSCALL_COUNT\n");
  fprintf(fp, "0\t19000006\tOTHERS_COUNT\n");
  fprintf(fp, "0\t10000007\tSYSCALL_BUF\n");
  fprintf(fp, "0\t13000008\tNET_SKBADDR\n");
  fprintf(fp, "0\t19000008\tOTHERS_SKBADDR\n");
  fprintf(fp, "0\t10000009\tSYSCALL_LEN\n");
  fprintf(fp, "0\t13000009\tNET_LEN\n");
  fprintf(fp, "0\t19000009\tOTHERS_LEN\n");
  fprintf(fp, "0\t10000010\tSYSCALL_NAME\n");
  fprintf(fp, "0\t13000010\tNET_NAME\n");
  fprintf(fp, "0\t13000011\tNET_RC\n");
  fprintf(fp, "0\t10000012\tSYSCALL_UFDS\n");
  fprintf(fp, "0\t10000013\tSYSCALL_NFDS\n");
  fprintf(fp, "0\t10000014\tSYSCALL_TIMEOUT_MSECS\n");

  free(syscalls_root);
  free(syscalls);
  free(kerncalls_root);
  free(kerncalls);
  free(softirqs_root);
  free(softirqs);
  free(irqhandler_root);
  free(irqhandler);
}
