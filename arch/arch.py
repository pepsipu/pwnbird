import angr


class Binary64:
    def __init__(self, project: angr.Project):
        self.project = project
        self.main = self.get_main()

    # because rdi *always* contains the first param for libc main, rdi will contain the address of the main function.
    # find last write to rdi and get that value to get main
    def get_main(self) -> int:
        _start = self.project.factory.block(self.project.entry).vex
        for statement in reversed(_start.statements):
            # if write & register is rdi
            if statement.tag == 'Ist_Put' and statement.offset == 72:
                return statement.data.con.value