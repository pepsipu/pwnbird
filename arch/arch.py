import angr


class Binary64:
    functions = {}

    def __init__(self, project: angr.Project):
        self.project = project
        self.symbols = list(project.loader.symbols)
        self.main = self.get_main()

    # because rdi *always* contains the first param for libc main, rdi will contain the address of the main function.
    # find last write to rdi and get that value to get main
    # also, handle the case where libc main ISN'T being used and the entry is the main function
    def get_main(self) -> int:
        if not any(symbol.name == '__libc_start_main' for symbol in self.symbols):
            return self.project.entry
        _start = self.project.factory.block(self.project.entry).capstone
        for insn in reversed(_start.insns):
            # if write & register is rdi
            if insn.mnemonic == 'mov' and insn.reg_name(insn.operands[0].value.reg) == 'rdi':
                return insn.operands[1].value.imm
