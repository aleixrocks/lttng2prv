#include "listEvents.h"

/*
 * Removes substring torm from input string dest
 */
static int rmsubstr(char *_dest, char *_torm);

static int
rmsubstr(char *dest, char *torm)
{
        int ret = 0;

        if ((dest = strstr(dest, torm)) != NULL) {
                const size_t len = strlen(torm);
                char *copyEnd;
                char *copyFrom = dest + len;

                while ((copyEnd = strstr(copyFrom, torm)) != NULL) {
                        memmove(dest, copyFrom, copyEnd - copyFrom);
                        dest += copyEnd - copyFrom;
                        copyFrom = copyEnd + len;
                }
                memmove(dest, copyFrom, 1 + strlen(copyFrom));

                ret = 1;
        }

        return ret;
}

/*
 * Classifies and prints events found in the ctf tracefile
 */
void
listEvents(struct bt_context *bt_ctx, FILE *fp)
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
        struct Events *remove;

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
        for (i = 0; i < cnt; i++) {
                /* Add 1 to the event_id to reserve 0 for exit */
                event_id = bt_ctf_get_decl_event_id(list[i]) + 1;
                event_name = strndup(bt_ctf_get_decl_event_name(list[i]),
                    strlen(bt_ctf_get_decl_event_name(list[i])));

                if ((strstr(event_name, "syscall_entry") != NULL) &&
                    (strstr(event_name, "syscall_entry_exit") == NULL)) {
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
                /*
                 * For softirq and irq_handler types we manually specify the
                 * event_value IDs instead of using the one provided by lttng.
                 * This way we always use the same values for these events.
                 */
                } else if ((strstr(event_name, "softirq_raise") != NULL) ||
                    (strstr(event_name, "softirq_entry") != NULL)) {
                        softirqs->id = 2;
                        if (rmsubstr(event_name, "_entry")) {
                                softirqs->id = 1;
                        }
                        softirqs->name = (char *) malloc(strlen(event_name) + 1);
                        strncpy(softirqs->name, event_name, strlen(event_name) + 1);
                        softirqs->next = (struct Events*) malloc(sizeof(struct Events));
                        softirqs = softirqs->next;
                        softirqs->next = NULL;
                } else if (strstr(event_name, "irq_handler_entry") != NULL) {
                        irqhandler->id = 1;
                        rmsubstr(event_name, "_entry");
                        irqhandler->name = (char *) malloc(strlen(event_name) + 1);
                        strncpy(irqhandler->name, event_name, strlen(event_name) + 1);
                        irqhandler->next = (struct Events*) malloc(sizeof(struct Events));
                        irqhandler = irqhandler->next;
                        irqhandler->next = NULL;
                } else if ((strstr(event_name, "netif_") != NULL) ||
                    (strstr(event_name, "net_dev_") != NULL)) {
                        netcalls->id = event_id;
                        netcalls->name = (char *) malloc(strlen(event_name) + 1);
                        strncpy(netcalls->name, event_name, strlen(event_name) + 1);
                        netcalls->next = (struct Events*) malloc(sizeof(struct Events));
                        netcalls = netcalls->next;
                        netcalls->next = NULL;
                } else if (strstr(event_name, "_exit") == NULL) {
                        kerncalls->id = event_id;
                        kerncalls->name = (char *) malloc(strlen(event_name) + 1);
                        strncpy(kerncalls->name, event_name, strlen(event_name) + 1);
                        kerncalls->next = (struct Events*) malloc(sizeof(struct Events));
                        kerncalls = kerncalls->next;
                        kerncalls->next = NULL;
                }
                free(event_name);
        }

        fprintf(fp, "EVENT_TYPE\n"
            "0\t20000000\tSTATUS\n"
            "VALUES\n"
            "0\tUSERMODE\n"
            "1\tSYSCALL\n"
            "2\tSOFT_IRQ\n"
            "3\tIRQ\n"
            "4\tNETWORK\n"
            "5\tWAIT_CPU\n"
            "6\tWAIT_BLOCK\n\n\n");
 
        fprintf(fp, "EVENT_TYPE\n"
            "0\t10000000\tSystem Call\n"
            "VALUES\n");

        syscalls = syscalls_root;
        while(syscalls->next != NULL) {
                fprintf(fp, "%" PRIu64 "\t%s\n", syscalls->id, syscalls->name);
                remove = syscalls;
                syscalls = syscalls->next;
                free(remove->name);
                free(remove);
        }
        fprintf(fp, "0\texit\n\n\n");

        fprintf(fp, "EVENT_TYPE\n"
            "0\t10100000\tSoft IRQ\n"
            "VALUES\n");

        softirqs = softirqs_root;
        while(softirqs->next != NULL) {
                fprintf(fp, "%" PRIu64 "\t%s\n", softirqs->id, softirqs->name);
                remove = softirqs;
                softirqs = softirqs->next;
                free(remove->name);
                free(remove);
        }
        fprintf(fp, "0\texit\n\n\n");

        fprintf(fp, "EVENT_TYPE\n"
            "0\t10200000\tIRQ Handler\n"
            "VALUES\n");

        irqhandler = irqhandler_root;
        while(irqhandler->next != NULL) {
                fprintf(fp, "%" PRIu64 "\t%s\n",
                    irqhandler->id, irqhandler->name);
                remove = irqhandler;
                irqhandler = irqhandler->next;
                free(remove->name);
                free(remove);
        }
        fprintf(fp, "0\texit\n\n\n");

        fprintf(fp, "EVENT_TYPE\n"
            "0\t10300000\tNetwork Calls\n"
            "VALUES\n");

        netcalls = netcalls_root;
        while(netcalls->next != NULL) {
                fprintf(fp, "%" PRIu64 "\t%s\n", netcalls->id, netcalls->name);
                remove = netcalls;
                netcalls = netcalls->next;
                free(remove->name);
                free(remove);
        }
        fprintf(fp, "0\texit\n\n\n");

        fprintf(fp, "EVENT_TYPE\n"
            "0\t10900000\tOthers\n"
            "VALUES\n");

        kerncalls = kerncalls_root;
        while(kerncalls->next != NULL) {
                fprintf(fp, "%" PRIu64 "\t%s\n",
                    kerncalls->id, kerncalls->name);
                remove = kerncalls;
                kerncalls = kerncalls->next;
                free(remove->name);
                free(remove);
        }
        fprintf(fp, "0\texit\n\n\n");

        fprintf(fp, "EVENT_TYPE\n");
        fprintf(fp, "0\t10000001\tSYSCALL_RET\n");
        fprintf(fp, "0\t10200001\tIRQ_RET\n");
        fprintf(fp, "0\t10900001\tOTHERS_RET\n");
        fprintf(fp, "0\t10000002\tSYSCALL_FD\n");
        fprintf(fp, "0\t10000003\tSYSCALL_SIZE\n");
        fprintf(fp, "0\t10900003\tOTHERS_SIZE\n");
        fprintf(fp, "0\t10000004\tSYSCALL_CMD\n");
        fprintf(fp, "0\t10000005\tSYSCALL_ARG\n");
        fprintf(fp, "0\t10000006\tSYSCALL_COUNT\n");
        fprintf(fp, "0\t10900006\tOTHERS_COUNT\n");
        fprintf(fp, "0\t10000007\tSYSCALL_BUF\n");
        fprintf(fp, "0\t10300008\tNET_SKBADDR\n");
        fprintf(fp, "0\t10900008\tOTHERS_SKBADDR\n");
        fprintf(fp, "0\t10000009\tSYSCALL_LEN\n");
        fprintf(fp, "0\t10300009\tNET_LEN\n");
        fprintf(fp, "0\t10900009\tOTHERS_LEN\n");
        fprintf(fp, "0\t10000010\tSYSCALL_NAME\n");
        fprintf(fp, "0\t10300010\tNET_NAME\n");
        fprintf(fp, "0\t10300011\tNET_RC\n");
        fprintf(fp, "0\t10000012\tSYSCALL_UFDS\n");
        fprintf(fp, "0\t10000013\tSYSCALL_NFDS\n");
        fprintf(fp, "0\t10000014\tSYSCALL_TIMEOUT_MSECS\n");
        fprintf(fp, "0\t99999999\tLost Events\n");

        free(syscalls);
        free(kerncalls);
        free(softirqs);
        free(irqhandler);
        free(netcalls);
}

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=9 shiftwidth=8
expandtab foldmethod=syntax cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */

