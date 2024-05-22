from binaryninja import log
from .arch.arch_abstract import Arch
from .arch.arch_x86_64 import x8664Arch
from .os_models.os_abstract import Os
from .memory.registers import Regs
from .memory.sym_memory import Memory
from .sym_solver import Solver
from .utility.expr_wrap_util import symbolic
from .expr import BV, BVV


class State(object):
    def __init__(self, executor, os: Os, arch: Arch = x8664Arch(), page_size: int = 0x1000):
        self.page_size = page_size
        self.arch = arch
        self.mem = Memory(self, page_size, arch.bits(),
                          not executor.init_with_zero)
        self.regs = Regs(self)
        self.solver = Solver(self)
        self.os = os
        self.events = list()
        self.insn_history = set()
        self.llil_ip = None
        self.executor = executor
        self.symbolic_buffers = list()
        self._ipreg = self.arch.getip_reg()
        self._bits = self.arch.bits()

    def __str__(self):
        return "<SymState 0x{id:x} @ 0x{addr:0{width}X}>".format(
            id=id(self),
            addr=self.get_ip(),
            width=(self._bits+3) // 4
        )

    def __repr__(self):
        return self.__str__()

    def get_ip(self):
        ip = getattr(self.regs, self._ipreg)
        assert not symbolic(ip)
        return ip.value

    def address_page_aligned(self, addr):
        return addr >> self.mem.index_bits << self.mem.index_bits

    def initialize_stack(self, stack_base):
        setattr(self.regs, self.arch.get_stack_pointer_reg(),
                BVV(stack_base, self._bits))
        setattr(self.regs, self.arch.get_base_pointer_reg(),
                BVV(stack_base, self._bits))

    def stack_push(self, val: BV):
        stack_pointer = getattr(self.regs, self.arch.get_stack_pointer_reg())
        new_stack_pointer = stack_pointer - self._bits // 8
        self.mem.store(new_stack_pointer, val, endness=self.arch.endness())
        setattr(self.regs, self.arch.get_stack_pointer_reg(), new_stack_pointer)

    def stack_pop(self):
        stack_pointer = getattr(self.regs, self.arch.get_stack_pointer_reg())
        res = self.mem.load(stack_pointer, self._bits //
                            8, endness=self.arch.endness())
        new_stack_pointer = stack_pointer + self._bits // 8
        setattr(self.regs, self.arch.get_stack_pointer_reg(), new_stack_pointer)
        return res

    def set_ip(self, new_ip):
        ip = getattr(self.regs, self._ipreg)
        if not symbolic(ip):
            self.executor._update_state_history(self, ip.value)
        setattr(self.regs, self._ipreg, BVV(new_ip, self._bits))

    def copy(self, solver_copy_fast=False):
        new_state = State(self.executor, self.os.copy(),
                          self.arch, self.page_size)
        new_state.mem = self.mem.copy(new_state)
        new_state.regs = self.regs.copy(new_state)
        new_state.solver = self.solver.copy(new_state, solver_copy_fast)
        new_state.events = list(self.events)
        new_state.insn_history = set(self.insn_history)
        new_state.symbolic_buffers = list(self.symbolic_buffers)
        new_state.llil_ip = self.llil_ip

        return new_state

    def merge_symb_buffers(self, other):
        self_buffers_name = [b[0].name for b in self.symbolic_buffers]
        for el in other.symbolic_buffers:
            buff = el[0]
            if buff.name not in self_buffers_name:
                self.symbolic_buffers.append(el)

    def merge(self, other):
        assert isinstance(other, State)
        assert self.arch.__class__ == other.arch.__class__
        assert self.os.__class__ == other.os.__class__
        assert self.get_ip() == other.get_ip()
        assert self.llil_ip == other.llil_ip

        _, _, merge_condition = self.solver.compute_solvers_difference(
            other.solver)
        self.solver.merge(other.solver)
        self.mem.merge(other.mem, merge_condition)
        self.regs.merge(other.regs, merge_condition)
        self.os.merge(other.os, merge_condition)
        self.events.append(
            (
                "merged with %s" % str(other),
                other.events[:]  # TODO delete common events
            )
        )
        self.insn_history |= other.insn_history
