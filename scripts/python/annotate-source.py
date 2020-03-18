import bisect
import os
import re
import subprocess
import sys

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
    '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

class EventProcessor:
    def __init__(self):
        self.dsos = {}
        self.sources = {}
        self.total_events = 0

    def process_event(self, attr, sample, comm, ev_name, raw_buf, callchain, dso=None, symbol=None):
        sample = next((frame for frame in callchain if self.annotatable(frame)), None)
        if sample:
            self.process_sample(**sample)
        self.total_events += 1

    def process_sample(self, ip, dso, sym=None):
        source, lineno = self.retrieve_dso(dso).source_lineno(ip)
        print(source + ':' + str(lineno))
        self.retrieve_source(source).increment_samples(lineno)

    def retrieve_dso(self, dso):
        if dso not in self.dsos:
            self.dsos[dso] = DynamicSharedObject(dso)
        return self.dsos[dso]

    def retrieve_source(self, source):
        if source not in self.sources:
            self.sources[source] = Source(source)
        return self.sources[source]

    def annotatable(self, sample):
        # TODO: remove the hard coding
        return sample.get('dso') and sample['dso'] not in ['[vdso]', '[kernel.kallsyms]', '/lib/x86_64-linux-gnu/libc-2.27.so', '/lib/x86_64-linux-gnu/libpthread-2.27.so']

class DynamicSharedObject:
    def __init__(self, path):
        entries = []
        source = None
        for line in subprocess.check_output(['objdump', '--dwarf=decodedline', path]).splitlines():
            match = re.match('^(CU: )?(?P<source>.+):$', line)
            if match:
                source = match.group('source')
            else:
                entry = re.split('\s+', line)
                if len(entry) >= 3 and source and entry[0] == os.path.basename(source):
                    entries.append((source, entry[1], int(entry[2], 0)))

        # List of `(source, lineno, address)` sorted by `address` for bisect
        self.entries = sorted(entries, key=lambda entry: entry[2])
        self.keys = [entry[2] for entry in self.entries]

        self.path_resolver = DynamicSharedObject.PathResolver(path)

    def source_lineno(self, address):
        entry = self.entries[bisect.bisect_right(self.keys, address) - 1]
        return (self.path_resolver.expand_path(entry[0], address=address), entry[1])

    class PathResolver:
        def __init__(self, dso):
            dwarf_info = subprocess.check_output(['objdump', '--dwarf=info', dso])
            entries = []
            for match in re.finditer('\n\s+<[\da-f]+>\s+DW_AT_comp_dir\s+: \([^)]+\): (?P<comp_dir>.+)' +
                                    '(\n\s+<[\da-f]+>\s+DW_AT_ranges\s+: .+)?' +
                                     '\n\s+<[\da-f]+>\s+DW_AT_low_pc\s+: (?P<low_pc>0x[\da-f]+)\n', dwarf_info):
                entries.append((match.group('comp_dir'), int(match.group('low_pc'), 0)))

            # List of `(comp_dir, low_pc)` sorted by `low_pc` for bisect
            self.entries = sorted(entries, key=lambda entry: entry[1])
            self.keys = [entry[1] for entry in self.entries]

            self.abs_paths = {}

        def expand_path(self, path, address):
            if os.path.isabs(path):
                return path
            elif path in self.abs_paths:
                return self.abs_paths[path]
            else:
                self.abs_paths[path] = os.path.normpath(
                    os.path.join(self.comp_dir(address), path))
                return self.abs_paths[path]

        def comp_dir(self, address):
            entry = self.entries[bisect.bisect_right(self.keys, address) - 1]
            return entry[0]

# lineno => samples
class Source:
    def __init__(self, path):
        self.path = path
        self.last_lineno = 0 # TODO: implement
        self.lineno_samples = {}

    def increment_samples(self, lineno):
        self.lineno_samples[lineno] = self.samples(lineno) + 1

    def samples(self, lineno):
        return self.lineno_samples.get(lineno, 0)

class SourceAnnotator:
    def __init__(self, total_events):
        self.total_events = total_events

    def annotate(self, source):
        pass # TODO: implement


def trace_begin():
    global processor
    processor = EventProcessor()

def process_event(event):
    # TODO: show processed traces as progress?
    processor.process_event(**event)

def trace_end():
    annotator = SourceAnnotator(processor.total_events)
    for source in processor.sources:
        annotator.annotate(source)
    print(processor.total_events) # TODO: remove
