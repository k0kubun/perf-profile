# encoding: utf-8
import argparse
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
        return sample.get('dso') and self.retrieve_dso(sample['dso']).annotatable

class DynamicSharedObject:
    def __init__(self, path):
        self.annotatable = False
        if path.startswith('[') and path.endswith(']'): # [kernel.kallsyms], [vdso]
            return
        print('Reading ' + path + '...')
        try:
            decodedline = subprocess.check_output(['objdump', '--dwarf=decodedline', path])
        except subprocess.CalledProcessError:
            return

        entries = []
        source = None
        for line in decodedline.splitlines():
            match = re.match('^(CU: )?(?P<source>.+):$', line)
            if match:
                source = match.group('source')
            else:
                entry = re.split('\s+', line)
                if len(entry) >= 3 and source and entry[0] == os.path.basename(source):
                    entries.append((source, int(entry[1]), int(entry[2], 0)))
        if not entries:
            print('Skipped %s (no debug_line)' % path)
            return

        # List of `(source, lineno, address)` sorted by `address` for bisect
        self.entries = sorted(entries, key=lambda entry: entry[2])
        self.keys = [entry[2] for entry in self.entries]

        self.path_resolver = DynamicSharedObject.PathResolver(path)
        self.annotatable = True

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

class Source:
    def __init__(self, path):
        self.path = path
        self.lineno_samples = {}

    def increment_samples(self, lineno):
        self.lineno_samples[lineno] = self.samples(lineno) + 1

    def samples(self, lineno):
        return self.lineno_samples.get(lineno, 0)

class SourceAnnotator:
    MIN_PERCENT = 0.1
    MED_PERCENT = 0.5
    TOP_PERCENT = 5.0
    SURROUND_LINES = 5

    RED = u'\u001b[31m'
    GREEN = u'\u001b[32m'
    CLEAR = u'\u001b[0m'

    def __init__(self, out, total_events, pretty, min_percent):
        self.out = out
        self.total_events = total_events
        self.pretty = pretty
        self.min_percent = min_percent if min_percent else self.MIN_PERCENT

    def annotate(self, source):
        lineno_rates = self.calc_and_filter_rates(source.lineno_samples)
        if not lineno_rates:
            return

        try:
            with open(source.path, 'r') as f:
                lines = f.readlines()
        except IOError as e:
            self.puts('\nFailed to annotate: %s' % source.path)
            self.puts(str(e))
            return
        linenos = self.pick_linenos(lineno_rates.keys(), len(lines))

        self.puts('\nFrom: %s' % source.path)
        prev_lineno = None
        for lineno in linenos:
            if prev_lineno and lineno != prev_lineno + 1:
                self.puts()
            prev_lineno = lineno

            line = lines[lineno - 1].rstrip()
            if lineno in lineno_rates:
                rate = lineno_rates[lineno]
                self.puts(self.prettify('[%6d (%5.2f%%)] |%6d | [%s]', rate) % (
                    source.lineno_samples[lineno], rate, lineno, line))
            else:
                self.puts(self.prettify('                |%6d | %s') % (lineno, line))

    def prettify(self, text, rate=0.0):
        if not self.pretty:
            return text.replace('[', '').replace(']', '')

        if rate >= self.TOP_PERCENT:
            color = self.RED
        elif rate >= self.MED_PERCENT:
            color = self.GREEN
        else:
            color = ''
        return text.replace('[', color).replace(']', self.CLEAR).replace('|', u'│')

    def calc_and_filter_rates(self, lineno_samples):
        rates = {}
        for lineno, samples in lineno_samples.items():
            rate = 100.0 * samples / self.total_events
            if rate > self.min_percent:
                rates[lineno] = rate
        return rates

    def pick_linenos(self, rated_linenos, max_lineno):
        linenos = []
        min_lineno = 1
        for rated_lineno in sorted(rated_linenos):
            beg_lineno = max(min_lineno, rated_lineno - self.SURROUND_LINES)
            end_lineno = min(rated_lineno + self.SURROUND_LINES, max_lineno)
            for lineno in range(beg_lineno, end_lineno + 1):
                linenos.append(lineno)
            min_lineno = end_lineno + 1
        return linenos

    def puts(self, text=''):
        self.out.write('%s\n' % text.encode('utf-8'))


def trace_begin():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-pager', action='store_true', help='disable running less')
    parser.add_argument('--no-pretty', action='store_true', help='disable color and unicode')
    parser.add_argument('--min-percent', type=float, help='minimum rate to be shown')

    global cmd_args
    cmd_args = parser.parse_args()

    global processor
    processor = EventProcessor()

def process_event(event):
    if sys.stdout.isatty():
        print('Processed: %d\r' % processor.total_events),
    processor.process_event(**event)

def trace_end():
    if not sys.stdout.isatty() or cmd_args.no_pager:
        popen = None
        out = sys.stdout
    else:
        popen = subprocess.Popen(['less', '-R'], stdin=subprocess.PIPE)
        out = popen.stdin

    annotator = SourceAnnotator(out=out, pretty=(sys.stdout.isatty() and not cmd_args.no_pretty),
                                total_events=processor.total_events, min_percent=cmd_args.min_percent)
    for source in processor.sources.values():
        try:
            annotator.annotate(source)
        except IOError: # pager closed
            break

    if popen:
        popen.stdin.close()
        os.waitpid(popen.pid, 0)
