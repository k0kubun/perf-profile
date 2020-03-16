# coding: utf-8
import os
import sys

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
    '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

class EventProcessor:
    def __init__(self):
        self.total_events = 0
        self.sources = set()
        self.dsos = set()

    def process_event(self, attr, sample, comm, ev_name, raw_buf, callchain, dso=None, symbol=None):
        sample = next((frame for frame in callchain if self.annotatable(frame)), None)
        if sample:
            self.process_sample(**sample)
        self.total_events += 1

    def process_sample(self, ip, dso, sym=None):
        print((dso, ip))

    def annotatable(self, sample):
        # TODO: remove the hard coding
        return sample.get('dso') and sample['dso'] not in ['[kernel.kallsyms]', '/lib/x86_64-linux-gnu/libc-2.27.so']

# lineno => samples
class Source:
    def __init__(self, path):
        self.path = path

# address_range => (filename, lineno)
class DynamicSharedObject:
    def __init__(self, path):
        self.path = path

class SourceAnnotator:
    def __init__(self, total_events):
        self.total_events = total_events

    def annotate(self, source):
        pass

def trace_begin():
    global processor
    processor = EventProcessor()

def process_event(event):
    processor.process_event(**event)

def trace_end():
    annotator = SourceAnnotator(processor.total_events)
    for source in processor.sources:
        annotator.annotate(source)
