from ..expr import BVV, BVS
from . import others as models_other
from . import libc as models_libc
from . import unistd as models_unistd
from . import string as models_string
from . import teensy as models_teensy

def reval_model(val, nbits):
    return lambda state, view: BVV(val, nbits)

library_functions = {
    'CRC32': models_libc.crc32,
    '_HNDL_STREAM_GetLastError': models_libc.false,
    'streamBuffCreate' : models_libc.streamBuffCreate_handler,
    'streamBuffRelease' : models_libc.streamBuffRelease_handler,
    '_HNDL_STREAM_ReadStream' : models_libc.streamBuffGet_handler,
    'HNDL_STREAM_ReadStream' : models_libc.streamBuffGet_handler,
    'streamBuffGet' : models_libc.streamBuffGet_handler,
    '_HNDL_STREAM_SeekStream' : models_libc.streamBuffSeek_handler,
    'HNDL_STREAM_SeekStream' : models_libc.streamBuffSeek_handler,
    'streamBuffSeek' : models_libc.streamBuffSeek_handler,
    '_HNDL_STREAM_TellStream' : models_libc.streamBuffPos_handler,
    'HNDL_STREAM_TellStream' : models_libc.streamBuffPos_handler,
    'streamBuffPos' : models_libc.streamBuffPos_handler,
    '_HNDL_STREAM_GetLength' : models_libc.streamBuffLen_handler,
    'HNDL_STREAM_GetLength' : models_libc.streamBuffLen_handler,
    'LOG_error':        models_libc.log_error_handler,
    'free':           models_libc.free_handler,
    '_free':           models_libc.free_handler,
    '_stack_chk_fail': models_libc.stack_chk_fail_handler,
    'stack_chk_fail': models_libc.stack_chk_fail_handler,
    'printf':           models_libc.printf_handler,
    '__printf_chk':     models_libc.printf_chk_handler,
    'scanf':            models_libc.scanf_handler,
    '__isoc99_scanf':   models_libc.scanf_handler,
    'sscanf':           models_libc.sscanf_handler,
    '__isoc99_sscanf':  models_libc.sscanf_handler,
    'getchar':          models_libc.getchar_handler,
    'putchar':          models_libc.putchar_handler,
    'puts':             models_libc.puts_handler,
    'fgets':            models_libc.fgets_handler,
    'strcmp':           models_string.strcmp_handler,
    'strlen':           models_string.strlen_handler,
    'strcpy':           models_string.strcpy_handler,
    'strncpy':          models_string.strncpy_handler,
    'isxdigit':         models_libc.isxdigit_handler,
    'atoi':             models_libc.atoi_handler,
    'atol':             models_libc.atol_handler,
    'atoll':            models_libc.atol_handler,
    'malloc':           models_libc.malloc_handler,
    'calloc':           models_libc.calloc_handler,
    'read':             models_unistd.read_handler,
    'write':            models_unistd.write_handler,
    'memcmp':           models_string.memcmp_handler,
    'memset':           models_string.memset_handler,
    'time':             models_other.time_handler,
    'gmtime_r':             models_other.gmtime_handler,
    'stat':             models_unistd.stat_handler,
    '__xstat':          models_unistd.xstat_handler,
    'exit':             models_libc.exit_handler,

    # Antidebug
    'ptrace':           models_libc.ptrace_handler,

    # C++
    '_Znwm':            models_libc.malloc_handler,
    '_Znwj':            models_libc.malloc_handler,

    # concrete models
    'strtoul':          models_libc.strtoul_handler,
    'srand':            models_libc.srand_handler,
    'rand':             models_libc.rand_handler,

    # models Teensy Board
    # Print::println(int)
    '_ZN5Print7printlnEi':   models_teensy.println_handler,
    # Print::println(char*)
    '_ZN5Print7printlnEPKc': models_teensy.println_handler
}
