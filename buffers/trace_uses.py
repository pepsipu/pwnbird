import capstone

param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']


class BufferTracer:
    def __init__(self, reference):
        self.reference = reference
        self.fp = self.check_if_function_param()

    # references which load the value at or address of the buffer into a register before a function call and do not
    # modify the buffer should be treated as passing the address of or value at the buffer to a function
    # because blocks are terminated by calls/syscalls/rets, checking if a buffer is used in a function is equivalent to
    # checking if the buffer is present in any of the 6 parameter registers at the end of the block.
    # due to it's very broad nature (load register & call) a reference should be checked to be a function param last
    def check_if_function_param(self):
        block = self.reference['block']
        # if this block doesn't call a function or we are using the buffer as a destination it can't be a function param
        if block.capstone.insns[-1].mnemonic != 'call' or self.reference['opcode_index'] == 0:
            return False
        regs = {}
        # the initial reference to the buffer will be moved into a register, which will be marked
        referencing_insn: capstone.CsInsn = block.capstone.insns[self.reference['instruction_index']]
        regs[referencing_insn.reg_name(referencing_insn.operands[0].value.reg)] = 'buf_mark'
        # track all register activity up until the call a function
        # all registers except the one from the referencing instruction will be marked as not containing the buffer
        # until they have gotten a mov from a register containing the buffer
        insn: capstone.CsInsn
        for insn in block.capstone.insns[self.reference['instruction_index'] + 1:-1]:
            if insn.mnemonic != 'mov':
                continue
            op_types = []
            for operand in insn.operands:
                op_types.append(operand.type)
                if operand.type == capstone.x86.X86_OP_REG:
                    register = insn.reg_name(operand.value.reg)
                    if register not in regs:
                        regs[register] = False
            if all(op_type == capstone.x86.X86_OP_REG for op_type in op_types):
                # symbolic mov
                regs[insn.reg_name(insn.operands[0].value.reg)] = regs[insn.reg_name(insn.operands[1].value.reg)]
            if op_types[0] == capstone.x86.X86_OP_REG and op_types[1] == capstone.x86.X86_OP_IMM:
                regs[insn.reg_name(insn.operands[0].value.reg)] = insn.operands[1].value.imm
        if any(val == 'buf_mark' if reg in param_regs else False for reg, val in regs.items()):
            return {
                'regs': regs,
                'address': block.capstone.insns[-1].operands[0].value.imm  # call addr
            }
