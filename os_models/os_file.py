from ..memory.sym_file import SymFile
from .os_abstract import Os


class FileSession(object):
    def __init__(self, fd, symfile, mode):
        self.fd = fd
        self.symfile = symfile
        self.mode = mode  # for now, ignored
        self.seek_idx = 0

    def __str__(self):
        return "<FileSession {filename} @ {seek} - {fd}>".format(
            filename=self.symfile.filename,
            fd=self.fd,
            seek=self.seek_idx
        )

    def __repr__(self):
        return self.__str__()

    # TODO: whence?
    def seek(self, idx):
        self.seek_idx = idx

    def ftell(self):
        return self.seek_idx

    def file_size(self):
        return self.symfile.file_size

    def read(self, size: int) -> tuple[int, list]:
        self.symfile.seek(self.seek_idx)
        self.seek_idx += size
        return self.symfile.read(size)

    def write(self, data: list):
        self.symfile.seek(self.seek_idx)
        self.symfile.write(data)
        self.seek_idx += len(data)

    def copy(self, new_symfile):
        res = FileSession(self.fd, new_symfile, self.mode)
        res.seek(self.seek_idx)
        return res


class OsFileHandler(Os):
    # os that handles files
    def __init__(self):
        self.next_descriptor = 0
        self.descriptors_map = {}  # descriptor to file session
        self.filesystem = {}       # filename to symfile object

    def open(self, filename, mode, size=4096, template=None):
        # print(f"open for filename={filename}, mode={mode}")
        if filename in self.filesystem:
            symfile = self.filesystem[filename]
        else:
            symfile = SymFile(filename, size=size, template=template)
            self.filesystem[filename] = symfile
        for fd in self.descriptors_map:
            if self.descriptors_map[fd].symfile.filename == filename:
                return fd
        fd = self.next_descriptor
        file_session = FileSession(fd, symfile, mode)
        self.descriptors_map[fd] = file_session

        self.next_descriptor += 1
        # print(f"open:returned fd={fd}")
        return fd

    def is_open(self, fd):
        print(f"is_open for fd={fd}")
        return fd in self.descriptors_map

    def seek(self, fd: int, idx: int):
        print(f"seek for fd={fd}, offset={idx}")
        assert fd in self.descriptors_map

        session = self.descriptors_map[fd]
        session.seek(idx)

    def ftell(self, fd: int):
        print(f"ftell for fd={fd}")
        assert fd in self.descriptors_map

        session = self.descriptors_map[fd]
        return session.ftell()

    def file_size(self, fd: int):
        print(f"file_size for fd={fd}")
        assert fd in self.descriptors_map

        session = self.descriptors_map[fd]
        return session.file_size()

    def read(self, fd: int, size: int) -> tuple[int, list]:
        #print(f"read for fd={fd}, size={size}")
        assert fd in self.descriptors_map

        session = self.descriptors_map[fd]
        return session.read(size)

    def write(self, fd: int, data: list):
        #print(f"write for fd={fd}, data={data}")
        assert fd in self.descriptors_map

        session = self.descriptors_map[fd]
        return session.write(data)

    def close(self, fd: int):
        print(f"close for fd={fd}")
        assert fd in self.descriptors_map
        del self.descriptors_map[fd]

    def copy_to(self, other):
        for filename in self.filesystem:
            other.filesystem[filename] = self.filesystem[filename].copy()
        for fd in self.descriptors_map:
            other.descriptors_map[fd] = self.descriptors_map[fd].copy(
                other.filesystem[self.descriptors_map[fd].symfile.filename]
            )
