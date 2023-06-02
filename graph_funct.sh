#!/bin/bash
TRACE_DIR=/sys/kernel/debug/tracing
echo > $TRACE_DIR/set_ftrace_filter
echo > $TRACE_DIR/current_tracer
echo nop > $TRACE_DIR/current_tracer

echo function_graph > $TRACE_DIR/current_tracer
# depth of the function calls
echo 5 > max_graph_depth
echo http_server_worker > $TRACE_DIR/set_graph_function


echo 1 > $TRACE_DIR/tracing_on
./htstress -n 100 -c 1 -t 4 http://localhost:8081/
echo 0 > $TRACE_DIR/tracing_on
