#!/bin/bash

BT_HOME=${HOME}/Projects/babeltrace

export LD_LIBRARY_PATH=${BT_HOME}/lib/.libs:${BT_HOME}/formats/ctf/.libs:${LD_LIBRARY_PATH}

`dirname $0`/build/src/lttng2prv $@

# vim: filetype=sh:tabstop=2:softtabstop=2:textwidth=80
