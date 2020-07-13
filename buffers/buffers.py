from buffers import trace_uses


class StackBuffer:
    def __init__(self, rbp_offset):
        self.references = []
        self.usages = []
        self.vulnerabilities = []
        self.rbp_offset = rbp_offset

    def add_reference(self, reference):
        self.references.append(reference)

    def check_usages(self):
        self.usages = [trace_uses.BufferTracer(reference) for reference in self.references]
