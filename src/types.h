#include <inttypes.h>

enum
{
	OPT_NONE = 0,
	OPT_OUTPUT,
	OPT_HELP
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
