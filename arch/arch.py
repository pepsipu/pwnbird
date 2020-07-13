import angr
from arch import functions
from buffers import buffers


class Binary64:

    def __init__(self, project: angr.Project):
        self.project = project
        self.functions = []
        self.symbols = list(project.loader.symbols)
        self.main = self.get_main()
        if self.main == -1:
            print('Could not find main function. Please specify it.')
            exit(1)
        self.cfg = self.project.analyses.CFGEmulated(keep_state=True, starts=[self.main])
        self.functions.append(functions.Function(self.cfg.kb.functions[self.main], self))
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
        return -1

    def pp_vulnerabilities(self):
        for function in self.functions:
            buffer: buffers.StackBuffer
            for buffer in function.stack_frame.frame_buffers.values():
                for vulnerability in buffer.vulnerabilities:
                    print(f'[function {function.function.demangled_name}]: found vulnerability "{vulnerability["type"]}" in buffer [rbp{hex(buffer.rbp_offset)}]')
                    if vulnerability["type"] == 'oob':
                        print(f'\t buffer size is "{function.stack_frame.calculate_buffer_size(buffer.rbp_offset)}" when the call to "{vulnerability["function"]}" allows write of size "{vulnerability["write_size"]}"')
