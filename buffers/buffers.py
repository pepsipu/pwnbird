class Buffer:
    def __init__(self):
        self.size = 0


class StackBuffer(Buffer):
    def __init__(self):
        super().__init__()


class StaticBuffer(Buffer):
    pass


class HeapBuffer(Buffer):
    pass
