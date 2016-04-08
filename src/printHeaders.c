#define UNUSED(x) (void)(x)

#include "types.h"
#include <glib.h>
#include <babeltrace/ctf/events.h>

void
printPRVHeader(struct bt_context *ctx, FILE *fp,
    GHashTable *tid_info_ht, int nresources)
{
        UNUSED(ctx);
        //*offset -= trace_times.first_stream_timestamp;

        time_t now = time(0);
        struct tm *local = localtime(&now);
        uint64_t ftime = trace_times.last_stream_timestamp -
            trace_times.first_stream_timestamp;

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
            g_hash_table_size(tid_info_ht) /* nAppl */
            //1 // Temporarily we use tasks, not appls
        );

        GHashTableIter ht_iter;
        gpointer key, value;
        g_hash_table_iter_init(&ht_iter, tid_info_ht);

        //fprintf(fp, "%d(", g_hash_table_size(tid_info_ht));
        while (g_hash_table_iter_next(&ht_iter, &key, &value)) {
                fprintf(fp, "1(1:1):");
        }
        /* Remove last colon */
        fseek(fp, -1, SEEK_CUR);
        fprintf(fp, ")\n");
}

void
printROW(FILE *fp, GHashTable *tid_info_ht, GList *tid_prv_l,
    GHashTable *irq_name_ht, GList *irq_prv_l, const uint32_t ncpus,
    const uint32_t nsoftirqs)
{
        gpointer value;
        uint32_t rcount = 0;
        GList *list;

        fprintf(fp, "LEVEL CPU SIZE %d\n",
            ncpus + nsoftirqs + g_hash_table_size(irq_name_ht));
        while (rcount < ncpus) {
                fprintf(fp, "CPU %d\n", rcount + 1);
                rcount++;
        }

        rcount = 0;
        while (rcount < nsoftirqs) {
                fprintf(fp, "SOFTIRQ %d\n", rcount + 1);
                rcount++;
        }

        while (irq_prv_l != NULL) {
                value = g_hash_table_lookup(irq_name_ht, irq_prv_l->data);
                fprintf(fp, "IRQ %d %s\n",
                    GPOINTER_TO_INT(irq_prv_l->data), (const char *)value);
                irq_prv_l = irq_prv_l->next;
        }
        fprintf(fp, "\n\n");

        list = tid_prv_l;
        fprintf(fp, "LEVEL APPL SIZE %d\n", g_hash_table_size(tid_info_ht));
        //fprintf(fp, "LEVEL TASK SIZE %d\n", g_hash_table_size(tid_info_ht));
        while (list != NULL) {
                value = g_hash_table_lookup(tid_info_ht, list->data);
                fprintf(fp, "%s\n", (const char *)value);
                list = list->next;
        }

        list = tid_prv_l;
        fprintf(fp, "\nLEVEL THREAD SIZE %d\n", g_hash_table_size(tid_info_ht));
        while (list != NULL) {
                value = g_hash_table_lookup(tid_info_ht, list->data);
                fprintf(fp, "%s\n", (const char *)value);
                list = list->next;
        }

        g_list_free(list);
}

void
printPCFHeader(FILE *fp)
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

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=8 shiftwidth=8 expandtab cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */
