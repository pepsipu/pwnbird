import types

import angr
import capstone

from buffers import buffers


class Stack:
    frame_buffers = {}

    def __init__(self, size, kb_function):
        self.size = size
        self.function = kb_function

    def add_offset(self, rbp_offset, address, block, instruction_index, opcode_index):
        sb: buffers.StackBuffer
        if rbp_offset not in self.frame_buffers:
            sb = buffers.StackBuffer(rbp_offset)
            self.frame_buffers[rbp_offset] = sb
        else:
            sb = self.frame_buffers[rbp_offset]
        sb.add_reference({
            address: address,
            block: block,
            instruction_index: instruction_index,
            opcode_index: opcode_index,
        })


class Function:
    def __init__(self, kb_function: angr.knowledge_plugins.Function):
        self.function = kb_function
        self.blocks = list(self.function.blocks)
        self.stack_frame = Stack(self.get_stack_size(), kb_function)
        self.find_stack_buffers()

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
            for i, insn in block.capstone.insns:
                operand: capstone.x86.X86Op
                for k, operand in enumerate(insn.operands):
                    # if it derefs rbp + some displacement, it's probably working on a stack buffer
                    if operand.type == capstone.x86.X86_OP_MEM and insn.reg_name(operand.value.mem.base) == 'rbp':
                        self.stack_frame.add_offset(operand.value.mem.disp, block, i, k)