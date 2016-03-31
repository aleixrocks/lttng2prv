/* Get all arguments from a call and print them */

#include <glib.h>
#include <string.h>
#include <babeltrace/ctf/events.h>

void
getArgValue(struct bt_ctf_event *event, uint64_t event_type,
    GHashTable *arg_types_ht, char *fields)
{
        const struct bt_definition *scope;
        struct bt_definition **fieldList;
        unsigned int count = 0;
        unsigned int iter;
        gpointer type;
        const struct bt_declaration *fieldDecl;
        int64_t intval = 0;
        uint64_t uintval = 0;


        scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
        bt_ctf_get_field_list(event, scope,
            (const struct bt_definition * const **)&fieldList, &count);

        if (!bt_ctf_field_get_error())
        {
                for (iter = 0; iter < count; iter++)
                {
                        type = g_hash_table_lookup(arg_types_ht,
                            bt_ctf_field_name(fieldList[iter]));
                        fieldDecl = bt_ctf_get_decl_from_def(fieldList[iter]);

                        if (type != NULL)
                        {
                                if (bt_ctf_get_int_signedness(fieldDecl))
                                {
                                        intval = bt_ctf_get_int64(fieldList[iter]);
                                        if (!bt_ctf_field_get_error())
                                        {
                                                sprintf(
                                                    fields + strlen(fields),
                                                    ":%lu:%li",
                                                    event_type +
                                                    GPOINTER_TO_INT(type),
                                                    intval);
                                        }
                                }else
                                {
                                        uintval = bt_ctf_get_uint64(fieldList[iter]);
                                        if (!bt_ctf_field_get_error())
                                        {
                                                sprintf(
                                                    fields + strlen(fields),
                                                    ":%lu:%lu",
                                                    event_type +
                                                    GPOINTER_TO_INT(type),
                                                    uintval);
                                        }
                                }
                        }
                }
        }
}

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=8 shiftwidth=8 expandtab cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */
