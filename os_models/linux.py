from ..models import linux_syscalls as models
from ..expr import Bool
from .os_file import OsFileHandler
from ..target.syscall import RegSyscallAbi


class Linux(OsFileHandler):
    SYSCALL_TABLE = {}

    def __init__(self):
        super().__init__()
        self.stdin_fd = self.open("__stdin",  "r--", size=0, template = None)
        self.stdout_fd = self.open("__stdout", "-w-", size=0, template = None)

    def get_syscall_by_number(self, n: int):
        if n not in self.SYSCALL_TABLE:
            return None
        return self.SYSCALL_TABLE[n]

    def get_stdin_stream(self):
        session = self.descriptors_map[self.stdin_fd]
        session_idx = session.seek_idx
        session.seek(0)
        res = session.read(session.symfile.file_size)
        session.seek(session_idx)

        return res

    def get_stdout_stream(self):
        session = self.descriptors_map[self.stdout_fd]
        session_idx = session.seek_idx
        session.seek(0)
        res = session.read(session.symfile.file_size)
        session.seek(session_idx)

        return res

    def copy_to(self, other):
        super().copy_to(other)
        other.stdin_fd = self.stdin_fd
        other.stdout_fd = self.stdout_fd


class Linuxi386(Linux):
    SYSCALL_TABLE = {
        0: None,
        3: models.read_handler,
        4: models.write_handler
    }

    def get_syscall_abi(self, view, arch):
        return RegSyscallAbi(
            "eax",
            ["ebx", "ecx", "edx", "esi", "edi", "ebp"],
            "eax",
        )

    def copy(self):
        res = Linuxi386()
        super().copy_to(res)
        return res

    def merge(self, other, merge_condition: Bool):
        assert isinstance(other, Linuxi386)
        pass  # TODO implement this


class Linuxia64(Linux):
    SYSCALL_TABLE = {
        0: models.read_handler,
        1: models.write_handler,
        2: None
    }

    def get_syscall_abi(self, view, arch):
        return RegSyscallAbi(
            "rax",
            ["rdi", "rsi", "rdx", "r10", "r8", "r9"],
            "rax",
        )

    def copy(self):
        res = Linuxia64()
        super().copy_to(res)
        return res

    def merge(self, other, merge_condition: Bool):
        assert isinstance(other, Linuxia64)
        pass  # TODO implement this


class LinuxArmV7(Linux):

    SYSCALL_TABLE = {
        0x900003: models.read_handler,
        0x900004: models.write_handler
    }

    def get_syscall_abi(self, view, arch):
        return RegSyscallAbi(
            "r7",
            ["r0", "r1", "r2", "r3", "r4", "r5", "r6"],
            "r0",
        )

    def copy(self):
        res = LinuxArmV7()
        super().copy_to(res)
        return res

    def merge(self, other, merge_condition: Bool):
        assert isinstance(other, LinuxArmV7)
        pass  # TODO implement this


class LinuxAArch64(Linux):

    SYSCALL_TABLE = {
        63: models.read_handler,   # sys_read
        64: models.write_handler,  # sys_write
    }

    def get_syscall_abi(self, view, arch):
        return RegSyscallAbi(
            "x8",
            ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            "x0",
        )

    def copy(self):
        res = LinuxAArch64()
        super().copy_to(res)
        return res

    def merge(self, other, merge_condition: Bool):
        assert isinstance(other, LinuxAArch64)
        pass  # TODO implement this


class LinuxRiscV(Linux):

    SYSCALL_TABLE = {
        63: models.read_handler,   # sys_read
        64: models.write_handler,  # sys_write
    }

    def get_syscall_abi(self, view, arch):
        return RegSyscallAbi(
            "a7",
            ["a0", "a1", "a2", "a3", "a4", "a5"],
            "a0",
        )

    def copy(self):
        res = LinuxRiscV()
        super().copy_to(res)
        return res

    def merge(self, other, merge_condition: Bool):
        assert isinstance(other, LinuxRiscV)
        pass  # TODO implement this
