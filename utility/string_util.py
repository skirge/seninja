from string import ascii_uppercase, ascii_lowercase, digits
from ..expr import BV, BVV, And, Or
from .expr_wrap_util import split_bv_in_list


def str_to_int(s):
    res = ""
    for c in s:
        res += hex(ord(c))[2:]
    res += "00"
    return int(res, 16)


def str_to_bv_list(s, terminator=False):
    res = list()
    for c in s:
        res.append(BVV(ord(c), 8))
    if terminator:
        res += [BVV(0, 8)]
    return res


def str_to_bv(s, terminator=False):
    if len(s) == 0:
        return None

    res = BVV(ord(s[0]), 8)
    for c in s[1:]:
        res = res.Concat(BVV(ord(c), 8))
    if terminator:
        res = res.Concat(BVV(0, 8))
    return res


def int_to_str(i):
    s = hex(i)[2:]
    res = ""
    for i in range(0, len(s), 2):
        res += chr(int(s[i] + s[i+1], 16))
    return res


def as_bytes(bv: BV):
    for i in range(bv.size, 0, -8):
        yield bv.Extract(i-1, i-8)


def get_byte(bv: BV, i: int):
    return bv.Extract(bv.size-i*8-1, bv.size-i*8-8)


def constraint_alphanumeric_string(bv, state):
    for bv in split_bv_in_list(bv, 8):
        state.solver.add_constraints(
            Or(
                And(bv >= ord("a"), bv <= ord("z")),
                And(bv >= ord("A"), bv <= ord("Z")),
                And(bv >= ord("0"), bv <= ord("9"))
            )
        )


def constraint_ascii_string(bv, state):
    for bv in split_bv_in_list(bv, 8):
        state.solver.add_constraints(
            bv >= 0x20, bv <= 0x7E
        )

MAX_PATTERN_LENGTH = 20280

class MaxLengthException(Exception):
    pass

class WasNotFoundException(Exception):
    pass

def pattern_gen(length):
    """
    Generate a pattern of a given length up to a maximum
    of 20280 - after this the pattern would repeat
    """
    if length >= MAX_PATTERN_LENGTH:
        raise MaxLengthException('ERROR: Pattern length exceeds maximum of %d' % MAX_PATTERN_LENGTH)

    pattern = ''
    for upper in ascii_uppercase:
        for lower in ascii_lowercase:
            for digit in digits:
                if len(pattern) < length:
                    pattern += upper+lower+digit
                else:
                    out = pattern[:length]
                    return out

def pattern_search(search_pattern):
    """
    Search for search_pattern in pattern.  Convert from hex if needed
    Looking for needle in haystack
    """
    needle = search_pattern

    try:
        if needle.startswith('0x'):
            # Strip off '0x', convert to ASCII and reverse
            needle = needle[2:]
            needle = bytearray.fromhex(needle).decode('ascii')
            needle = needle[::-1]
    except (ValueError, TypeError) as e:
        raise

    haystack = ''
    for upper in ascii_uppercase:
        for lower in ascii_lowercase:
            for digit in digits:
                haystack += upper+lower+digit
                found_at = haystack.find(needle)
                if found_at > -1:
                    return found_at

    raise WasNotFoundException('Couldn`t find %s (%s) anywhere in the pattern.' %
          (search_pattern, needle))
