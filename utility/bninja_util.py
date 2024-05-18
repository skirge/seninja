from binaryninja import SymbolType
from .exceptions import UnsupportedOs
from ..os_models.linux import Linuxi386, Linuxia64, LinuxArmV7
from ..os_models.windows import Windows


sticky_fun = None
def get_function(view, address):
    global sticky_fun

    funcs = view.get_functions_at(address)
    if len(funcs) == 0:
        funcs = view.get_functions_containing(address)

    if len(funcs) > 1:
        print("WARNING: more than one function at {addr:x}".format(
            addr=address
        ))
        # Prefer the last translated function when there is an ambiguity.
        # This is just an heuristic, it does not solve the problem in general.
        funcs = sorted(
            funcs,
            key=lambda f: \
                0 if (sticky_fun is not None and sticky_fun.name == f.name)
                else 1)

    if len(funcs) == 0:
        return None
    sticky_fun = funcs[0]
    return funcs[0]


def get_imported_functions_and_addresses(view):
    res_functions = dict()
    res_addresses = dict()

    symbols = view.symbols
    for name in symbols:
        symb_types = symbols[name]
        if not isinstance(symb_types, list):
            symb_types = [symb_types]

        for symb_type in symb_types:
            if symb_type.type == SymbolType.ImportedFunctionSymbol:
                res_functions[symb_type.address] = symb_type.name
            if symb_type.type == SymbolType.ImportAddressSymbol or symb_type.type == SymbolType.ExternalSymbol:
                res_addresses[symb_type.address] = symb_type.name

                if "@IAT" in symb_type.name or "@GOT" in symb_type.name:
                    addr = int.from_bytes(
                        view.read(symb_type.address, view.arch.address_size),
                        'little' if view.arch.endianness.name == 'LittleEndian' else 'big'
                    )
                    res_functions[addr] = symb_type.name.replace(
                        "@IAT" if "@IAT" in symb_type.name else "@GOT", "")

    return res_functions, res_addresses


def get_addr_next_inst(view, addr):
    return addr + view.get_instruction_length(addr)


def parse_disasm_str(disasm_str):
    inst_name = disasm_str.split(" ")[0]
    parameters = ''.join(disasm_str.split(" ")[1:]).split(",")
    return inst_name, parameters


def get_address_after_merge(view, address):
    func = get_function(view, address)
    llil = func.llil.get_instruction_start(address, func.arch)
    return func.llil[llil].address


def find_os(view):
    platform_name = view.platform.name

    if platform_name == 'linux-x86_64':
        return Linuxia64()
    if platform_name == 'mac-x86_64':
        return Linuxia64()
    elif platform_name == 'linux-x86':
        return Linuxi386()
    elif platform_name == 'linux-armv7':
        return LinuxArmV7()
    elif platform_name == 'linux-thumb2':
        return LinuxArmV7()
    elif platform_name == 'windows-x86':
        return Windows()
    elif platform_name == 'windows-x86_64':
        return Windows()

    raise UnsupportedOs(platform_name)

class MockValue(object):

    def __init__(self, v):
        self.value = v

class MockSymbol(object):

    def __init__(self, v):
        self.address = v

def get_from_code_refs(view, ip):
    addrs = view.get_code_refs_from(ip)
    # TODO: improve this
    addr = 0
    # TODO: may ask user to select one if more functions were found
    for a in addrs:
        if a != 0x0:
            addr = a
            break
    if addr != 0:
        sym = view.get_symbol_at(addr)
        return sym

def get_from_type_refs(view, ip):
    refs = view.get_code_refs_for_type_fields_from(ip)
    if refs:
        # TODO: What if more than one?
        t = refs[0]
        tt = view.types[t.name]
        if tt is None:
            raise Exception(f"Type references not found in view:{t}")
        m = None
        for mm in tt.members:
            if t.offset == mm.offset:
                m = mm
        if m is None:
            raise Exception(f"Member not found in type:{t}")
        if m.name in view.symbols:
            return view.symbols[m.name][0]
        else:
            return MockSymbol(0xDEADC0DE)
