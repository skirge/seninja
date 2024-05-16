import os

from ..utility.string_util import str_to_bv_list
from ..expr import BV, BVV
from .sym_flat_memory_not_paged import MemoryConcreteFlatNotPaged


class SymFile(object):
    def __init__(self, filename, symfile=None, size=0, template=None):
        self.filename = filename
        if size == 0:
            self.can_grow = True
        else:
            self.can_grow = False
        if symfile is None:
            self.data = MemoryConcreteFlatNotPaged(filename)
            self.seek_idx = 0
            self.file_size = size
        else:
            self.data = symfile.data.copy()
            self.seek_idx = symfile.seek_idx
            self.file_size = symfile.file_size
        if template is not None:
            fstats = os.stat(template)
            fsize = fstats.st_size
            if fsize > 0:
                with open(template, "rb") as f:
                    if size < fsize:
                        self.file_size = fsize
                    while (byte:=f.read(1)):
                        self.write([BVV(int.from_bytes(byte),8)])
                    self.seek(0)
                    print(f"[+] template file = {template} read into filename = {filename}, size={size}")
            else:
                print(f"[-] file {template} is empty!")

    def __str__(self):
        return "<SymFile %s, size: %s>" % (self.filename, self.file_size)

    def __repr__(self):
        return self.__str__()

    def seek(self, idx: int):
        self.seek_idx = idx

    def read(self, size: int) -> tuple[int, list]:
        res = []
        # TODO: do not read past the file
        if not self.can_grow:
            size = min(self.file_size-self.seek_idx, size)
        for i in range(self.seek_idx, self.seek_idx + size):
            res.append(self.data.load(BVV(i, self.data.bits), 1))

        self.seek_idx += size
        if self.can_grow:
            self.file_size = max(self.file_size, self.seek_idx)
        return size, res

    def write(self, data: list):
        count = 0
        for i, el in enumerate(data):
            assert isinstance(el, BV) and el.size == 8
            self.data.store(
                BVV(self.seek_idx + i, 64),
                el
            )
            self.seek_idx += 1
            count += 1
            if (not self.can_grow) and self.seek_idx > self.file_size:
                break
        if self.can_grow:
            self.file_size = max(self.file_size, self.seek_idx)
        return count

    def merge(self, other, merge_condition):
        pass  # not implemented

    def copy(self, state=None):
        return SymFile(self.filename, self)
