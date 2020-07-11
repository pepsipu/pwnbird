from buffers import buffers
from .vtypes import bof


def sanity_check_buffer(buffer: buffers.StackBuffer, binary):
    return {
        'bof': bof.BufferOverflow(buffer.usages, binary),
    }
