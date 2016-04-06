#pragma once
#ifndef TYPES_H
#define TYPES_H

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

enum
{
        STATE_USERMODE = 0,
        STATE_SYSCALL,
        STATE_SOFTIRQ,
        STATE_IRQ,
        STATE_NETWORK,
        STATE_WAIT_CPU,
        STATE_WAIT_BLOCK
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

#endif

/*
 * Modeline for space only BSD KNF code style
 */
/* vim: set textwidth=80 colorcolumn=+0 tabstop=8 softtabstop=8 shiftwidth=8 expandtab cinoptions=\:0l1t0+0.5s(0.5su0.5sm1: */
