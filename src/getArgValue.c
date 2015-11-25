/* Get all arguments from a call and print them */

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

#include "types.h"

void fillArgTypes(GHashTable *arg_types_ht)
{
	g_hash_table_insert(arg_types_ht, g_strndup("ret", 3), GINT_TO_POINTER(20000000));
	g_hash_table_insert(arg_types_ht, g_strndup("fd", 2), GINT_TO_POINTER(20000001));
	g_hash_table_insert(arg_types_ht, g_strndup("size", 4), GINT_TO_POINTER(20000002));
	g_hash_table_insert(arg_types_ht, g_strndup("cmd", 3), GINT_TO_POINTER(20000003));
	g_hash_table_insert(arg_types_ht, g_strndup("arg", 3), GINT_TO_POINTER(20000004));
	g_hash_table_insert(arg_types_ht, g_strndup("count", 5), GINT_TO_POINTER(20000005));
	g_hash_table_insert(arg_types_ht, g_strndup("buf", 3), GINT_TO_POINTER(20000006));
	g_hash_table_insert(arg_types_ht, g_strndup("skbaddr", 7), GINT_TO_POINTER(20000007));
	g_hash_table_insert(arg_types_ht, g_strndup("len", 3), GINT_TO_POINTER(20000008));
	g_hash_table_insert(arg_types_ht, g_strndup("name", 4), GINT_TO_POINTER(20000009));
	g_hash_table_insert(arg_types_ht, g_strndup("rc", 2), GINT_TO_POINTER(20000010));

}

void getArgValue(struct bt_ctf_event *event, GHashTable *arg_types_ht, char *fields)
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
	bt_ctf_get_field_list(event, scope, (const struct bt_definition * const **)&fieldList, &count);

	if (!bt_ctf_field_get_error())
	{
		for (iter = 0; iter < count; iter++)
		{
			type = g_hash_table_lookup(arg_types_ht, bt_ctf_field_name(fieldList[iter]));
			fieldDecl = bt_ctf_get_decl_from_def(fieldList[iter]);

			if (type != NULL)
			{
				if (bt_ctf_get_int_signedness(fieldDecl))
				{
					intval = bt_ctf_get_int64(fieldList[iter]);
					if (!bt_ctf_field_get_error())
					{
						sprintf(fields + strlen(fields), ":%d:%li", GPOINTER_TO_INT(type), intval);
					}
				}else
				{
					uintval = bt_ctf_get_uint64(fieldList[iter]);
					if (!bt_ctf_field_get_error())
					{
						sprintf(fields + strlen(fields), ":%d:%lu", GPOINTER_TO_INT(type), uintval);
					}
				}
			}
		}
	}
}
