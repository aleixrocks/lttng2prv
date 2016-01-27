#pragma once

#include <inttypes.h>
#include <stdbool.h>

#define debug(...) if (verbose) fprintf(stderr, __VA_ARGS__)

extern bool verbose;

enum
{
        OPT_NONE = 0,
        OPT_OUTPUT,
        OPT_TIMESTAMPS,
        OPT_VERBOSE
};

struct traceTimes
{
        uint64_t first_stream_timestamp;
        uint64_t last_stream_timestamp;
};

struct traceTimes trace_times;

struct Events
{
        uint64_t id;
        char *name;
        struct Events *next;
};

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=8 shiftwidth=8 expandtab cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */
