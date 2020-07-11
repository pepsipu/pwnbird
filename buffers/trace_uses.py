import enum


class BufferUsageTypes(enum.Enum):
    FUNCTION_PARAMETER = 0


class BufferTracer:
    def __init__(self, reference):
        self.reference = reference

    # references which load the value at or address of the buffer into a register before a function call and do not
    # modify the buffer should be treated as passing the address of or value at the buffer to a function
    # due to it's very broad nature (load register & call) a reference should be checked to be a function param last
    def check_function_param(self):
        pass
