import types

import angr
import capstone

from buffers import buffers
from vectors import vectors


class Stack:
    def __init__(self, size, kb_function):
        self.frame_buffers = {}
        self.size = size
        self.function = kb_function

    def get_buffer(self, rbp_offset):
        if rbp_offset not in self.frame_buffers:
            sb = buffers.StackBuffer(rbp_offset)
            self.frame_buffers[rbp_offset] = sb
            return sb
        else:
            return self.frame_buffers[rbp_offset]

    def add_offset(self, rbp_offset, block, instruction_index, opcode_index):
        sb: buffers.StackBuffer = self.get_buffer(rbp_offset)
        sb.add_reference({
            'block': block,
            'instruction_index': instruction_index,
            'opcode_index': opcode_index,
        })

    # calculating a buffer's size is asking the question "how much can i write before i hit another buffer or the end of
    # the stack (buffer 0)?". since writes happen from low address to high, we check how far the rbp offset is from
    # an adjacent buffer. so, we can sort the list of offsets and see how much the buffer can hold before it hits the
    # next offset
    def calculate_buffer_size(self, offset):
        sorted_buffers = [*self.frame_buffers.keys()]
        sorted_buffers.sort()
        sorted_buffers.insert(0, 0)
        return -(offset - sorted_buffers[sorted_buffers.index(offset) - 1])


class Function:
    def __init__(self, kb_function: angr.knowledge_plugins.Function, binary):
        self.function = kb_function
        self.binary = binary
        self.blocks = list(self.function.blocks)
        self.stack_frame = Stack(self.get_stack_size(), kb_function)
        self.find_stack_buffers()
        self.check_buffer_usages()
        self.sanity_check_buffers()

    def get_stack_size(self) -> int:
        insn: capstone.CsInsn
        for insn in self.blocks[0].capstone.insns:
            # growing the stack subs rsp, so we can read stack size from there
            if insn.mnemonic == 'sub' and insn.reg_name(insn.operands[0].value.reg) == 'rsp':
                return insn.operands[1].value.imm
        return -1

    def find_stack_buffers(self):
        for block in self.blocks:
            insn: capstone.CsInsn
            for i, insn in enumerate(block.capstone.insns):
                operand: capstone.x86.X86Op
                for k, operand in enumerate(insn.operands):
                    # if it derefs rbp + some displacement, it's probably working on a stack buffer
                    if operand.type == capstone.x86.X86_OP_MEM and insn.reg_name(operand.value.mem.base) == 'rbp':
                        self.stack_frame.add_offset(operand.value.mem.disp, block, i, k)

    def check_buffer_usages(self):
        frame_buffer: buffers.StackBuffer
        for frame_buffer in self.stack_frame.frame_buffers.values():
            frame_buffer.check_usages()

    def sanity_check_buffers(self):
        frame_buffer: buffers.StackBuffer
        for frame_buffer in self.stack_frame.frame_buffers.values():
            frame_buffer.vulnerabilities = vectors.sanity_check_buffer(frame_buffer, self.binary)

    def get_buffers(self):
        return self.stack_frame.frame_buffers
