import os
import sys
import time

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
    '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

def trace_begin():
    global event_num
    event_num = 0

def process_event(param_dict):
    global event_num
    event_num += 1
    print(param_dict['callchain'])

def trace_end():
    global event_num
    print(event_num)
