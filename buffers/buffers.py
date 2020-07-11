from buffers import trace_uses

class Buffer:
    def __init__(self):
        self.writes = []
        self.reads = []


class StackBuffer(Buffer):
    references = []

    def __init__(self, rbp_offset):
        super().__init__()
        self.rbp_offset = rbp_offset

    def add_reference(self, reference):
        self.references.append(reference)

    def check_usages(self):
        for reference in self.references:
            trace_uses.BufferTracer(reference)

class StaticBuffer(Buffer):
    pass


class HeapBuffer(Buffer):
    pass
