import math

from buffers import trace_uses
from arch import arch



class BufferOverflow:
    def __init__(self, usages, binary):
        self.usages = usages
        self.binary: arch.Binary64 = binary
        self.vulnerabilities = []
        self.checks()

    def checks(self):
        usage: trace_uses.BufferTracer
        for usage in self.usages:
            if usage.fp:
                # check if function called takes user input to write to buffer
                self.buffer_write_checks(usage.fp)

    def buffer_write_checks(self, fp):
        function_name = self.binary.cfg.kb.functions[fp['address']].demangled_name
        if function_name == 'gets':
            pass

    def get_vulnerabilities(self):
        pass
