import debugpy
from binaryninja import (
    BinaryReader, BinaryWriter,
    RegisterValueType, enums,
    log
)
from .sym_state import State
from .arch.arch_x86 import x86Arch
from .arch.arch_x86_64 import x8664Arch
from .arch.arch_armv7 import ArmV7Arch
from .models.function_models import library_functions
from .utility.expr_wrap_util import (
    bvv_from_bytes, symbolic
)
from .utility.exceptions import (
    UnimplementedInstruction, DivByZero, NoDestination,
    UnconstrainedIp, UnsatState, ExitException,
    UnimplementedModel, UnimplementedSyscall
)
from .expr import BV, BVV, BVS, Bool, BoolV, ITE
from .utility.bninja_util import (
    get_imported_functions_and_addresses,
    find_os,
    parse_disasm_str,
    get_from_code_refs,
    get_from_type_refs
)
from .utility.binary_ninja_cache import BNCache
from .memory.sym_memory import InitData
from .multipath.fringe import Fringe


class BNILVisitor(object):
    # thanks joshwatson
    # https://github.com/joshwatson/f-ing-around-with-binaryninja/blob/master/ep4-emulator/vm_visitor.py
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression, level=0):
        method_name = 'visit_{}'.format(expression.operation.name)
        log.log_debug(f"{' '*level}>{method_name}: expression={expression} @ {hex(expression.address)}")
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression,level+1)
        else:
            raise UnimplementedInstruction(expression.operation.name, self.executor.state.get_ip())
        log.log_debug(f"{' '*level}>{method_name}:value={value}")
        return value


class SymbolicVisitor(BNILVisitor):
    def __init__(self, executor):
        super(SymbolicVisitor, self).__init__()
        self.executor = executor

    def __str__(self):
        return "<SymVisitor @ SymExecutor 0x%x>" % \
            id(self.executor)

    def __repr__(self):
        return self.__str__()

    def _handle_symbolic_ip(self, expr, max_sol):
        state = self.executor.state
        sols = state.solver.evaluate_upto(expr, max_sol)
        return len(sols), sols

    # --- HANDLERS ---

    def visit_LLIL_CONST(self, expr,level):
        return BVV(expr.constant, max(expr.size, 1) * 8)

    def visit_LLIL_CONST_PTR(self, expr,level):
        return BVV(expr.constant, self.executor.arch.bits())

    def visit_LLIL_SET_REG(self, expr,level):
        dest = expr.dest.name
        src = self.visit(expr.src,level+1)

        # X86_64 fix
        if isinstance(self.executor.arch, x8664Arch):
            if dest in {
                'eax',  'ebx',  'ecx',  'edx',
                'edi',  'esi',  'esp',  'ebp',
                'r8d',  'r9d',  'r10d', 'r11d',
                'r12d', 'r13d', 'r14d', 'r15d'
            }:
                dest = ("r" + dest[1:]) if dest[0] == 'e' else dest[:-1]
                src = src.ZeroExt(32)

        if isinstance(src, Bool):
            src = ITE(
                src,
                BVV(1, 1).ZeroExt(expr.dest.info.size*8-1),
                BVV(0, 1).ZeroExt(expr.dest.info.size*8-1)
            )
        if src.size == 1:
            src = src.ZeroExt(8)

        setattr(self.executor.state.regs, dest, src)
        log.log_debug(f"{' '*level}>LLIL_SET_REG:{dest}={src}")
        return True

    def visit_LLIL_REG(self, expr,level):
        src = expr.src
        v = getattr(self.executor.state.regs, src.name)
        log.log_debug(f"{' '*level}>LLIL_REG:{src.name}={v}")
        return v

    def visit_LLIL_REG_SPLIT(self, expr,level):
        lo = getattr(self.executor.state.regs, expr.lo.name)
        hi = getattr(self.executor.state.regs, expr.hi.name)
        log.log_debug(f"{' '*level}>LLIL_REG_SPLIT:lo={lo},hi={hi}")
        return hi.Concat(lo)

    def visit_LLIL_SET_REG_SPLIT(self, expr,level):
        src = self.visit(expr.src,level+1)
        lo = expr.lo.name
        hi = expr.hi.name

        lo_val = src.Extract(src.size // 2 - 1, 0)
        hi_val = src.Extract(src.size - 1, src.size // 2)

        setattr(self.executor.state.regs, lo, lo_val)
        setattr(self.executor.state.regs, hi, hi_val)
        return True

    def visit_LLIL_SET_FLAG(self, expr,level):
        dest = expr.dest.name
        src = self.visit(expr.src,level+1)

        if isinstance(src, Bool):
            res = ITE(src, BVV(1, 1), BVV(0, 1))
        else:
            res = ITE(src == 0, BVV(0, 1), BVV(1, 1))
        self.executor.state.regs.flags[dest] = res
        log.log_debug(f"{' '*level}>LLIL_SET_FLAG:{dest}={res}")
        return True

    def visit_LLIL_FLAG(self, expr,level):
        src = expr.src.name
        return self.executor.state.regs.flags[src]

    def visit_LLIL_LOW_PART(self, expr,level):
        src = self.visit(expr.src,level+1)
        size = expr.size

        return src.Extract(size*8-1, 0)

    def visit_LLIL_ADD(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        if right.size > left.size:
            left = left.SignExt(right.size - left.size)
        if left.size > right.size:
            right = right.SignExt(left.size - right.size)

        return left + right

    def visit_LLIL_ADC(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)
        carry = self.visit(expr.carry,level+1)

        if right.size > left.size:
            left = left.SignExt(right.size - left.size)
        if left.size > right.size:
            right = right.SignExt(left.size - right.size)

        return left + right + carry.ZeroExt(left.size - 1)

    def visit_LLIL_ADD_OVERFLOW(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        # add with one more bit
        res = (BVV(0, 1).Concat(left) + BVV(0, 1).Concat(right))
        # check if overflow
        res = res.Extract(left.size, left.size)
        return res

    def visit_LLIL_SUB(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        if right.size > left.size:
            left = left.SignExt(right.size - left.size)
        if left.size > right.size:
            right = right.SignExt(left.size - right.size)

        return left - right

    def visit_LLIL_SBB(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)
        carry = self.visit(expr.carry,level+1)

        if right.size > left.size:
            left = left.SignExt(right.size - left.size)
        if left.size > right.size:
            right = right.SignExt(left.size - right.size)
        if carry.size < left.size:
            carry = carry.ZeroExt(left.size - carry.size)

        return left - (right + carry)

    def visit_LLIL_MUL(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        if right.size > left.size:
            left = left.SignExt(right.size - left.size)
        if left.size > right.size:
            right = right.SignExt(left.size - right.size)

        return left * right

    def visit_LLIL_MULS_DP(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert left.size == right.size
        left = left.SignExt(left.size)
        right = right.SignExt(right.size)
        return left * right

    def visit_LLIL_MULU_DP(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert left.size == right.size
        left = left.ZeroExt(left.size)
        right = right.ZeroExt(right.size)
        return left * right

    def visit_LLIL_DIVU(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        #assert left.size == right.size

        check_division_by_zero = self.executor.bncache.get_setting(
            "check_division_by_zero") == 'true'

        right = right.ZeroExt(left.size - right.size)
        if check_division_by_zero and self.executor.state.solver.satisfiable(extra_constraints=[right == 0]):
            print("WARNING: division by zero detected")
            errored = self.executor.state.copy(solver_copy_fast=True)
            errored.solver.add_constraints(right == 0)
            self.executor.put_in_errored(
                errored,
                "DIVU at %s (%d LLIL) division by zero" % (
                    hex(errored.get_ip()), self.executor.llil_ip)
            )

        self.executor.state.solver.add_constraints(right != 0)
        if not self.executor.state.solver.satisfiable():
            self.executor.put_in_errored(
                self.executor.state, "division by zero")
            raise DivByZero(self.executor.state.get_ip())

        div = left.UDiv(right)
        return div.Extract(expr.size * 8 - 1, 0)

    def visit_LLIL_DIVU_DP(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert left.size == 2*right.size

        check_division_by_zero = self.executor.bncache.get_setting(
            "check_division_by_zero") == 'true'

        right = right.ZeroExt(left.size - right.size)
        if check_division_by_zero and self.executor.state.solver.satisfiable(extra_constraints=[right == 0]):
            print("WARNING: division by zero detected")
            errored = self.executor.state.copy(solver_copy_fast=True)
            errored.solver.add_constraints(right == 0)
            self.executor.put_in_errored(
                errored,
                "DIVU_DP at %s (%d LLIL) division by zero" % (
                    hex(errored.get_ip()), self.executor.llil_ip)
            )

        self.executor.state.solver.add_constraints(right != 0)
        if not self.executor.state.solver.satisfiable():
            self.executor.put_in_errored(
                self.executor.state, "division by zero")
            raise DivByZero(self.executor.state.get_ip())

        div = left.UDiv(right)
        return div.Extract(expr.size * 8 - 1, 0)

    def visit_LLIL_DIVS_DP(self, expr,level):  # is it correct?
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert left.size == 2*right.size

        check_division_by_zero = self.executor.bncache.get_setting(
            "check_division_by_zero") == 'true'

        right = right.SignExt(left.size - right.size)
        if check_division_by_zero and self.executor.state.solver.satisfiable(extra_constraints=[right == 0]):
            print("WARNING: division by zero detected")
            errored = self.executor.state.copy(solver_copy_fast=True)
            errored.solver.add_constraints(right == 0)
            self.executor.put_in_errored(
                errored,
                "DIVS_DP at %s (%d LLIL) division by zero" % (
                    hex(errored.get_ip()), self.executor.llil_ip)
            )

        self.executor.state.solver.add_constraints(right != 0)
        if not self.executor.state.solver.satisfiable():
            self.executor.put_in_errored(
                self.executor.state, "division by zero")
            raise DivByZero(self.executor.state.get_ip())

        div = left / right
        return div.Extract(expr.size * 8 - 1, 0)

    def visit_LLIL_MODU_DP(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert left.size == 2*right.size

        check_division_by_zero = self.executor.bncache.get_setting(
            "check_division_by_zero") == 'true'

        right = right.ZeroExt(left.size - right.size)
        if check_division_by_zero and self.executor.state.solver.satisfiable(extra_constraints=[right == 0]):
            print("WARNING: division by zero detected")
            errored = self.executor.state.copy(solver_copy_fast=True)
            errored.solver.add_constraints(right == 0)
            self.executor.put_in_errored(
                errored,
                "MODU_DP at %s (%d LLIL) division by zero" % (
                    hex(errored.get_ip()), self.executor.llil_ip)
            )

        self.executor.state.solver.add_constraints(right != 0)
        if not self.executor.state.solver.satisfiable():
            self.executor.put_in_errored(
                self.executor.state, "division by zero")
            raise DivByZero(self.executor.state.get_ip())

        mod = left.URem(right)
        return mod.Extract(expr.size * 8 - 1, 0)

    def visit_LLIL_MODS_DP(self, expr,level):  # is it correct?
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert left.size == 2*right.size

        check_division_by_zero = self.executor.bncache.get_setting(
            "check_division_by_zero") == 'true'

        right = right.SignExt(left.size - right.size)
        if check_division_by_zero and self.executor.state.solver.satisfiable(extra_constraints=[right == 0]):
            print("WARNING: division by zero detected")
            errored = self.executor.state.copy(solver_copy_fast=True)
            errored.solver.add_constraints(right == 0)
            self.executor.put_in_errored(
                errored,
                "MODS_DP at %s (%d LLIL) division by zero" % (
                    hex(errored.get_ip()), self.executor.llil_ip)
            )

        self.executor.state.solver.add_constraints(right != 0)
        if not self.executor.state.solver.satisfiable():
            self.executor.put_in_errored(
                self.executor.state, "division by zero")
            raise DivByZero(self.executor.state.get_ip())

        mod = left.SRem(right)
        return mod.Extract(expr.size * 8 - 1, 0)

    def visit_LLIL_AND(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        if isinstance(left, Bool):
            left = ITE(left, BVV(1, 8), BVV(0, 8))
        if isinstance(right, Bool):
            right = ITE(right, BVV(1, 8), BVV(0, 8))

        if right.size > left.size:
            left = left.ZeroExt(right.size - left.size)
        if left.size > right.size:
            right = right.ZeroExt(left.size - right.size)

        return left & right

    def visit_LLIL_OR(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        if isinstance(left, Bool):
            left = ITE(left, BVV(1, 8), BVV(0, 8))
        if isinstance(right, Bool):
            right = ITE(right, BVV(1, 8), BVV(0, 8))

        if right.size > left.size:
            left = left.ZeroExt(right.size - left.size)
        if left.size > right.size:
            right = right.ZeroExt(left.size - right.size)

        return left | right

    def visit_LLIL_XOR(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        if right.size > left.size:
            left = left.ZeroExt(right.size - left.size)
        if left.size > right.size:
            right = right.ZeroExt(left.size - right.size)

        return left ^ right

    def visit_LLIL_NOT(self, expr,level):
        src = self.visit(expr.src,level+1)

        return src.__invert__()

    def visit_LLIL_NEG(self, expr,level):
        src = self.visit(expr.src,level+1)

        return src.__neg__()

    def visit_LLIL_LOAD(self, expr,level):
        src = self.visit(expr.src,level+1)
        size = expr.size
        log.log_debug(f"{' '*level}:LLIL_LOAD:src={src}, size={size}")
        loaded = self.executor.state.mem.load(
            src, size, endness=self.executor.arch.endness())

        return loaded

    def visit_LLIL_STORE(self, expr,level):
        dest = self.visit(expr.dest,level+1)
        src = self.visit(expr.src,level+1)
        assert expr.size*8 == src.size

        self.executor.state.mem.store(
            dest, src, endness=self.executor.arch.endness())
        return True

    def visit_LLIL_LSL(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert right.size <= left.size

        # the logical and arithmetic left-shifts are exactly the same
        return left << right.ZeroExt(left.size - right.size)

    def visit_LLIL_LSR(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert right.size <= left.size

        return left.LShR(
            right.ZeroExt(left.size - right.size)
        )

    def visit_LLIL_ROR(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert right.size <= left.size

        return left.RotateRight(
            right.ZeroExt(left.size - right.size)
        )

    def visit_LLIL_ROL(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert right.size <= left.size

        return left.RotateLeft(
            right.ZeroExt(left.size - right.size)
        )

    def visit_LLIL_ASL(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert right.size <= left.size

        return left << right.ZeroExt(left.size - right.size)

    def visit_LLIL_ASR(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        assert right.size <= left.size

        return left >> right.ZeroExt(left.size - right.size)

    def visit_LLIL_INTRINSIC(self, expr, level):
        log.log_info(f"LLIL_INTRINSIC:{expr.intrinsic.name} at {hex(expr.address)}")

    def visit_LLIL_CALL(self, expr,level):
        dest = self.visit(expr.dest,level+1)
        dest_fun_name = None

        sym = get_from_code_refs(self.executor.view, self.executor.ip, True)
        if sym is None:
            sym = get_from_type_refs(self.executor.view, self.executor.ip, True)
            if sym is not None:
                dest = BVV(sym.address, self.executor.arch.bits())
                dest_fun_name = self.executor.bncache.get_function_name(dest.value)
        else:
            dest = BVV(sym.address, self.executor.arch.bits())
            dest_fun_name = self.executor.bncache.get_function_name(dest.value)

        if dest_fun_name is None and symbolic(dest):
            raise UnconstrainedIp(self.executor.ip)
        if "thumb" in self.executor.view.arch.name and (dest.value & 1 != 0):
            dest.value = dest.value - 1
        curr_fun_name = self.executor.bncache.get_function_name(
            self.executor.ip)
        if dest_fun_name is None:
            if dest.value in self.executor.imported_functions:
                dest_fun_name = self.executor.imported_functions[dest.value]
            else:
                dest_fun_name = self.executor.bncache.get_function_name(dest.value)
        if dest_fun_name is None:
            # Last chance, look in symbols
            sym = self.executor.view.get_symbol_at(dest.value)
            if sym is None:
                raise Exception("Unable to find function name @ 0x%x" % dest.value)
            # If we are here, it is for sure a library function
            dest_fun_name = sym.name
            if dest_fun_name not in library_functions:
                raise UnimplementedModel(dest_fun_name, self.executor.ip)

        ret_addr = self.executor.ip + \
            self.executor.bncache.get_instruction_len(self.executor.ip)

        # save ret address
        self.executor.arch.save_return_address(
            self.executor.state, BVV(ret_addr, self.executor.arch.bits()))

        # check if we have an handler
        if dest_fun_name in library_functions:
            log.log_info(f"Running {dest_fun_name} builtin handler")
            res = library_functions[dest_fun_name](
                self.executor.state, self.executor.view)
            log.log_info(f"{dest_fun_name} builtin handler returned {res}")
            try:
                dest_fun = self.executor.bncache.get_function(dest.value)
                calling_convention = dest_fun.calling_convention
            except IndexError:
                # dest_fun is not a function (imported). We do not have the info about the calling convention..
                # Let's use the caller convention
                curr_fun = self.executor.bncache.get_function(self.executor.ip)
                calling_convention = curr_fun.calling_convention
            self.executor.arch.save_result_value(
                self.executor.state, calling_convention, res)

            # retrive return address
            dest = self.executor.arch.get_return_address(self.executor.state)
            dest_fun_name = curr_fun_name
            assert not symbolic(dest)  # cannot happen (right?)

        # check if imported
        elif dest.value in self.executor.imported_functions:
            name = self.executor.imported_functions[dest.value]
            if name[0]=='_':
                name = name[1:]
            if name not in library_functions:
                raise UnimplementedModel(name, self.executor.ip)

            res = library_functions[name](
                self.executor.state, self.executor.view)

            dest_fun = self.executor.bncache.get_function(dest.value)
            self.executor.arch.save_result_value(
                self.executor.state, dest_fun.calling_convention, res)

            # retrive return address
            dest = self.executor.arch.get_return_address(self.executor.state)
            dest_fun_name = curr_fun_name
            assert not symbolic(dest)  # cannot happen (right?)

        # change ip
        self.executor.update_ip(dest_fun_name, self.executor.bncache.get_llil_address(
            dest_fun_name, dest.value))

        self.executor._wasjmp = True
        return True

    def visit_LLIL_TAILCALL(self, expr,level):
        dest = self.visit(expr.dest,level+1)
        dest_fun_name = None

        sym = get_from_code_refs(self.executor.view, self.executor.ip, True)
        if sym is None:
            sym = get_from_type_refs(self.executor.view, self.executor.ip, True)
            if sym is not None:
                dest = BVV(sym.address, self.executor.arch.bits())
                dest_fun_name = self.executor.bncache.get_function_name(dest.value)
        else:
            dest = BVV(sym.address, self.executor.arch.bits())
            dest_fun_name = self.executor.bncache.get_function_name(dest.value)

        if dest_fun_name is None and symbolic(dest):
            raise UnconstrainedIp(self.executor.ip)
        log.log_debug(f"dest = {dest}")
        if "thumb" in self.executor.view.arch.name and (dest.value & 1 != 0):
            dest.value = dest.value - 1
        log.log_debug(f"dest = {dest}")
        if dest_fun_name is None: 
            if dest.value in self.executor.imported_functions:
                dest_fun_name = self.executor.imported_functions[dest.value]
            else:
                dest_fun_name = self.executor.bncache.get_function_name(dest.value)
        if dest_fun_name is None:
            # Last chance, look in symbols
            sym = self.executor.view.get_symbol_at(dest.value)
            if sym is None:
                raise Exception("Unable to find function name @ 0x%x" % dest.value)
            # If we are here, it is for sure a library function
            dest_fun_name = sym.name
            if dest_fun_name not in library_functions:
                raise UnimplementedModel(dest_fun_name, self.executor.ip)

        # check if we have an handler
        if dest_fun_name in library_functions:
            log.log_info(f"Running {dest_fun_name} builtin handler")
            res = library_functions[dest_fun_name](
                self.executor.state, self.executor.view)
            log.log_info(f"{dest_fun_name} builtin handler returned: {res}")
            calling_convention = "cdecl"
            dest_fun = self.executor.bncache.get_function(dest.value)
            if dest_fun is not None:
                calling_convention = dest_fun.calling_convention
            self.executor.arch.save_result_value(
                self.executor.state, calling_convention, res)

            # retrive return address
            dest = self.executor.arch.get_return_address(self.executor.state)
            if symbolic(dest):
                raise UnconstrainedIp(self.executor.ip)

            dest_fun_name = self.executor.bncache.get_function_name(dest.value)

        # check if imported
        if dest.value in self.executor.imported_functions:
            name = self.executor.imported_functions[dest.value]
            if name[0]=='_':
                name = name[1:]
            if name not in library_functions:
                raise UnimplementedModel(name, self.executor.ip)

            res = library_functions[name](
                self.executor.state, self.executor.view)

            dest_fun = self.executor.bncache.get_function(dest.value)
            self.executor.arch.save_result_value(
                self.executor.state, dest_fun.calling_convention, res)

            # retrive return address
            dest = self.executor.arch.get_return_address(self.executor.state)
            if symbolic(dest):
                raise UnconstrainedIp(self.executor.ip)

            dest_fun_name = self.executor.bncache.get_function_name(dest.value)

        # change ip
        self.executor.update_ip(dest_fun_name, self.executor.bncache.get_llil_address(
            dest_fun_name, dest.value))

        self.executor._wasjmp = True
        return True

    def visit_LLIL_JUMP(self, expr,level):
        destination = self.visit(expr.dest,level+1)

        if not symbolic(destination):
            # fast path. The destination is concrete
            dest_fun_name = self.executor.bncache.get_function_name(
                destination.value)
            self.executor.update_ip(dest_fun_name, self.executor.bncache.get_llil_address(
                dest_fun_name, destination.value))
            self.executor._wasjmp = True
            return True

        assert False  # implement this

    def visit_LLIL_JUMP_TO(self, expr,level):
        destination = self.visit(expr.dest,level+1)

        curr_fun_name = self.executor.bncache.get_function_name(
            self.executor.ip)

        if not symbolic(destination):
            # fast path. The destination is concrete
            self.executor.update_ip(curr_fun_name, self.executor.bncache.get_llil_address(
                curr_fun_name, destination.value))
            self.executor._wasjmp = True
            return True

        # symbolic IP path
        if self.executor.bncache.get_setting("use_bn_jumptable_targets") == 'true':
            max_num = len(expr.targets)
        else:
            max_num = 256
        num_ips, dest_ips = self._handle_symbolic_ip(destination, max_num)
        if num_ips == 256:
            self.executor.put_in_errored(
                self.executor.state, "Probably unconstrained IP")
            raise UnconstrainedIp()

        if num_ips == 0:
            self.executor.put_in_errored(
                self.executor.state, "No valid destination")
            raise NoDestination()

        for ip in dest_ips[1:]:
            new_state = self.executor.state.copy()
            new_state.solver.add_constraints(
                destination == ip
            )
            new_state.set_ip(ip.value)
            new_state.llil_ip = self.executor.bncache.get_llil_address(
                curr_fun_name, ip.value)
            self.executor.put_in_deferred(new_state)

        self.executor.update_ip(curr_fun_name, self.executor.bncache.get_llil_address(
            curr_fun_name, dest_ips[0].value))
        self.executor.state.solver.add_constraints(dest_ips[0] == destination)
        self.executor._wasjmp = True
        return True

        # ips = expr.targets
        # current_constraint = None
        # for dst_ip in ips:
        #     llil_index = self.executor.bncache.get_llil_address(
        #         curr_fun_name, dst_ip)
        #     if self.executor.state.solver.satisfiable([
        #         destination == dst_ip
        #     ]):
        #         if current_constraint is None:
        #             current_constraint = destination == dst_ip
        #             self.executor.update_ip(
        #                 curr_fun_name, llil_index)
        #         else:
        #             new_state = self.executor.state.copy()
        #             new_state.solver.add_constraints(
        #                 destination == dst_ip
        #             )
        #             new_state.set_ip(dst_ip)
        #             new_state.llil_ip = llil_index
        #             self.executor.put_in_deferred(new_state)

        # if current_constraint is None:
        #     return ErrorInstruction.NO_DEST

        # self.executor.state.solver.add_constraints(current_constraint)
        # self.executor._wasjmp = True
        # return True

    def visit_LLIL_IF(self, expr,level):
        condition = self.visit(expr.condition,level+1)
        true_llil_index = expr.true
        false_llil_index = expr.false

        save_unsat = self.executor.bncache.get_setting("save_unsat") == 'true'

        true_sat = True
        false_sat = True
        if isinstance(condition, BV):
            assert condition.size == 1
            condition = condition == 1

        if isinstance(condition, BoolV):
            # Fast path
            true_sat = condition.value
            false_sat = not condition.value
        else:
            if not self.executor.state.solver.satisfiable(extra_constraints=[
                condition
            ]):
                true_sat = False
            if not self.executor.state.solver.satisfiable(extra_constraints=[
                condition.Not()
            ]):
                false_sat = False

        curr_fun_name = self.executor.bncache.get_function_name(
            self.executor.ip)

        if true_sat and false_sat:
            true_state = self.executor.state
            false_state = self.executor.state.copy()

            true_state.solver.add_constraints(condition)
            self.executor.update_ip(curr_fun_name, true_llil_index)

            false_state.solver.add_constraints(condition.Not())
            false_state.set_ip(self.executor.bncache.get_address(
                curr_fun_name, false_llil_index))
            false_state.llil_ip = false_llil_index
            self.executor.put_in_deferred(false_state)
        elif true_sat and not false_sat:
            true_state = self.executor.state
            false_state = self.executor.state.copy() if save_unsat else None

            true_state.solver.add_constraints(condition)
            self.executor.update_ip(curr_fun_name, true_llil_index)

            if save_unsat:
                false_state.solver.add_constraints(condition.Not())
                import z3; false_state.solver._solver = z3.Solver()

                false_state.set_ip(self.executor.bncache.get_address(
                    curr_fun_name, false_llil_index))
                false_state.llil_ip = false_llil_index
                self.executor.put_in_unsat(false_state)
        elif not true_sat and false_sat:
            false_state = self.executor.state
            true_state = self.executor.state.copy() if save_unsat else None

            false_state.solver.add_constraints(condition.Not())
            self.executor.state = false_state
            self.executor.update_ip(curr_fun_name, false_llil_index)

            if save_unsat:
                true_state.solver.add_constraints(condition)
                import z3; true_state.solver._solver = z3.Solver()

                true_state.set_ip(self.executor.bncache.get_address(
                    curr_fun_name, true_llil_index))
                true_state.llil_ip = true_llil_index
                self.executor.put_in_unsat(true_state)
        else:
            true_state = self.executor.state.copy() if save_unsat else None
            false_state = self.executor.state.copy() if save_unsat else None

            if save_unsat:
                true_state.solver.add_constraints(condition)
                import z3; true_state.solver._solver = z3.Solver()

                true_state.set_ip(self.executor.bncache.get_address(
                    curr_fun_name, true_llil_index))
                true_state.llil_ip = true_llil_index
                self.executor.put_in_unsat(true_state)

                false_state.solver.add_constraints(condition.Not())
                import z3; false_state.solver._solver = z3.Solver()

                false_state.set_ip(self.executor.bncache.get_address(
                    curr_fun_name, false_llil_index))
                false_state.llil_ip = false_llil_index
                self.executor.put_in_unsat(false_state)

            self.executor.put_in_unsat(self.executor.state)
            raise UnsatState(self.executor.state.get_ip())

        self.executor._wasjmp = True
        return True

    def visit_LLIL_CMP_E(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left == right

    def visit_LLIL_CMP_NE(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left != right

    def visit_LLIL_CMP_SLT(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left < right

    def visit_LLIL_CMP_ULT(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left.ULT(right)

    def visit_LLIL_CMP_SLE(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left <= right

    def visit_LLIL_CMP_ULE(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left.ULE(right)

    def visit_LLIL_CMP_SGT(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left > right

    def visit_LLIL_CMP_UGT(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left.UGT(right)

    def visit_LLIL_CMP_SGE(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left >= right

    def visit_LLIL_CMP_UGE(self, expr,level):
        left = self.visit(expr.left,level+1)
        right = self.visit(expr.right,level+1)

        return left.UGE(right)

    def visit_LLIL_GOTO(self, expr,level):
        dest = expr.dest

        curr_fun_name = self.executor.bncache.get_function_name(
            self.executor.ip)
        self.executor.update_ip(curr_fun_name, dest)

        self.executor._wasjmp = True
        return True

    def visit_LLIL_RET(self, expr,level):
        dest = self.visit(expr.dest,level+1)

        if symbolic(dest):
            num_ips, dest_ips = self._handle_symbolic_ip(dest, 256)

            if num_ips == 256:
                self.executor.put_in_errored(
                    self.executor.state, "Probably unconstrained IP")
                raise UnconstrainedIp(self.executor.ip)
            if num_ips == 0:
                self.executor.put_in_errored(
                    self.executor.state, "No valid destination")
                raise NoDestination()

            for ip in dest_ips[1:]:
                dest_fun_name = self.executor.bncache.get_function_name(
                    ip.value)
                new_state = self.executor.state.copy()
                new_state.solver.add_constraints(
                    dest == ip
                )
                new_state.set_ip(ip.value)
                new_state.llil_ip = self.executor.bncache.get_llil_address(
                    dest_fun_name, ip.value)
                self.executor.put_in_deferred(new_state)

            dest_ip = dest_ips[0].value
        else:
            dest_ip = dest.value

        dest_fun_name = self.executor.bncache.get_function_name(dest_ip)
        if dest_fun_name is not None:
            self.executor.update_ip(
                dest_fun_name, self.executor.bncache.get_llil_address(dest_fun_name, dest_ip))
            self.executor._wasjmp = True
            return True
        else:
            raise ExitException()

    def visit_LLIL_PUSH(self, expr,level):
        src = self.visit(expr.src,level+1)

        self.executor.state.stack_push(src)
        return True

    def visit_LLIL_POP(self, expr,level):
        return self.executor.state.stack_pop()

    def visit_LLIL_SX(self, expr,level):
        src = self.visit(expr.src,level+1)
        dest_size = expr.size * 8

        assert src.size <= dest_size

        return src.SignExt(dest_size - src.size)

    def visit_LLIL_ZX(self, expr,level):
        src = self.visit(expr.src,level+1)
        dest_size = expr.size * 8

        assert src.size <= dest_size

        return src.ZeroExt(dest_size - src.size)

    def visit_LLIL_SYSCALL(self, expr,level):
        n_reg = self.executor.state.os.get_syscall_n_reg()
        n = getattr(self.executor.state.regs, n_reg)
        assert not symbolic(n)
        n = n.value

        handler = self.executor.state.os.get_syscall_by_number(n)
        if handler is None:
            raise UnimplementedSyscall(n)

        res = handler(self.executor.state)
        res_reg = self.executor.state.os.get_out_syscall_reg()
        setattr(self.executor.state.regs, res_reg, res)

        return True

    def visit_LLIL_NORET(self, expr,level):
        raise ExitException()

    def visit_LLIL_UNIMPL(self, expr,level):
        log.log_error(f"Unimplemented instruction:{expr} at {hex(expr.address)}")
