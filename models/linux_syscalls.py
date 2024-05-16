from ..utility.expr_wrap_util import symbolic
from ..utility.exceptions import ExitException, ModelError
from ..expr import BVV

MAX_SYM_READ_WRITE = 100


def read_handler(state):
    fd = state.syscall_abi.get_arg(state, 0)
    buf = state.syscall_abi.get_arg(state, 1)
    count = state.syscall_abi.get_arg(state, 2)

    if symbolic(fd) and state.solver.symbolic(fd):
        raise ModelError("linux_read", "symbolic fd not supported")
    fd = fd.value
    if not state.os.is_open(fd):
        return BVV(-9, 32) # EBADF

    if symbolic(count):
        count = state.solver.max(count)
        count = MAX_SYM_READ_WRITE if count > MAX_SYM_READ_WRITE else count
    else:
        count = count.value

    _, res = state.os.read(fd, count)
    for i, b in enumerate(res):
        state.mem.store(buf + i, b)

    state.events.append(
        "read from fd %d, count %d" % (fd, count)
    )
    return BVV(count, 32)


def write_handler(state):
    fd = state.syscall_abi.get_arg(state, 0)
    buf = state.syscall_abi.get_arg(state, 1)
    count = state.syscall_abi.get_arg(state, 2)

    if symbolic(fd) and state.solver.symbolic(fd):
        raise ModelError("linux_write", "symbolic fd not supported")
    fd = fd.value
    if not state.os.is_open(fd):
        return BVV(-9, 32) # EBADF

    if symbolic(count):
        count = state.solver.max(count)
        count = MAX_SYM_READ_WRITE if count > MAX_SYM_READ_WRITE else count
    else:
        count = count.value

    data = []
    for i in range(count):
        b = state.mem.load(buf + i, 1)
        data.append(b)
    state.os.write(fd, data)

    state.events.append(
        "write to fd %d, count %d" % (fd, count)
    )
    return BVV(count, 32)


def exit_handler(state):
    raise ExitException()
