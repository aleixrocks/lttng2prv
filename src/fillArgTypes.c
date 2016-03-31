#include "fillArgTypes.h"

void
fillArgTypes(GHashTable *arg_types_ht)
{
        g_hash_table_insert(arg_types_ht,
            g_strndup("ret", 3),
            GINT_TO_POINTER(1));
        g_hash_table_insert(arg_types_ht,
            g_strndup("fd", 2),
            GINT_TO_POINTER(2));
        g_hash_table_insert(arg_types_ht,
            g_strndup("size", 4),
            GINT_TO_POINTER(3));
        g_hash_table_insert(arg_types_ht,
            g_strndup("cmd", 3),
            GINT_TO_POINTER(4));
        g_hash_table_insert(arg_types_ht,
            g_strndup("arg", 3),
            GINT_TO_POINTER(5));
        g_hash_table_insert(arg_types_ht,
            g_strndup("count", 5),
            GINT_TO_POINTER(6));
        g_hash_table_insert(arg_types_ht,
            g_strndup("buf", 3),
            GINT_TO_POINTER(7));
        g_hash_table_insert(arg_types_ht,
            g_strndup("skbaddr", 7),
            GINT_TO_POINTER(8));
        g_hash_table_insert(arg_types_ht,
            g_strndup("len", 3),
            GINT_TO_POINTER(9));
        g_hash_table_insert(arg_types_ht,
            g_strndup("name", 4),
            GINT_TO_POINTER(10));
        g_hash_table_insert(arg_types_ht,
            g_strndup("rc", 2),
            GINT_TO_POINTER(11));
        g_hash_table_insert(arg_types_ht,
            g_strndup("ufds", 4),
            GINT_TO_POINTER(12));
        g_hash_table_insert(arg_types_ht,
            g_strndup("nfds", 4),
            GINT_TO_POINTER(13));
        g_hash_table_insert(arg_types_ht,
            g_strndup("timeout_msecs", 13),
            GINT_TO_POINTER(14));
}


/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=9 shiftwidth=8
expandtab foldmethod=syntax cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */

