# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2021 Christian Werling, Robert Buhren, Hans Niklas Jacob
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import struct

from .entry import DirectoryEntry, BiosDirectoryEntry
from .utils import NestedBuffer, fletcher32
from .file import File, BiosFile, SECONDARY_DIRECTORY_ENTRY_TYPES, TERTIARY_DIRECTORY_ENTRY_TYPES

from typing import List


class Directory(NestedBuffer):
    DIRECTORY_MAGICS = [b'$PSP', b'$PL2']
    HEADER_SIZE = 4 * 4

    ENTRY_CLASS = DirectoryEntry
    ENTRY_SIZE = DirectoryEntry.ENTRY_SIZE
    FILE_CLASS = File

    # Per-ROM budgets against crafted images with aliased or overlapping directories
    MAX_DIRECTORIES_PER_ROM = 4096
    MAX_ENTRIES_PER_ROM = 1 << 16

    ZEN_GENERATION_IDS = {'Zen 1'  : [b'\x00\x09\xBC', b'\x00\x0A\xBC'],
                          'Zen 2'  : [b'\x05\x0B\xBC', b'\x01\x0A\xBC'],
                          'Zen 3'  : [b'\x01\x0C\xBC', b'\x00\x0C\xBC'],
                          'Zen 4'  : [b'\x04\x0D\xBC', b'\x0B\x0D\xBC'],
                          'Zen 4/5': [b'\x03\x0D\xBC', b'\x01\x0D\xBC', b'\x00\x0E\xBC', b'\x0B\x0E\xBC',
                                      b'\x0C\x0E\xBC', b'\x0D\x0E\xBC', b'\x10\x0E\xBC', b'\x11\x0E\xBC']
                         }

    @classmethod
    def get_possible_zen_generation(cls, zen_generation_id):
        zen_generation = 'unknown'
        for possible_zen_generation in cls.ZEN_GENERATION_IDS:
            if zen_generation_id in cls.ZEN_GENERATION_IDS[possible_zen_generation]:
                zen_generation = possible_zen_generation

        return zen_generation

    class ParseError(Exception):
        pass

    @classmethod
    def bios_directory_class(cls):
        return BiosDirectory

    @classmethod
    def create_directories_if_not_exist(cls, offset, fet, zen_generation=None) -> List['Directory']:
        # Return or create and return found directories, depth-first: each directory is followed by its secondary
        # and then its tertiary directories. A worklist instead of recursion bounds the stack for long chains.
        directories_by_offset = fet.rom.directories_by_offset
        found_directories = []
        todo = [(offset, zen_generation, False)]
        while todo:
            offset, zen_generation, is_tertiary_pointer = todo.pop()
            if len(directories_by_offset) >= cls.MAX_DIRECTORIES_PER_ROM or fet.rom.entry_count >= cls.MAX_ENTRIES_PER_ROM:
                fet.psptool.ph.print_warning("Too many directories or entries in ROM, ignoring the rest")
                break
            try:
                if is_tertiary_pointer:
                    # Tertiary directories (double references introduced in Zen 4): resolve one more indirection
                    directory_body = fet.rom.get_bytes(offset, 32)
                    offset = int.from_bytes(directory_body[16:20], 'little')
                    zen_generation_id = directory_body[21:24]
                    zen_generation = cls.get_possible_zen_generation(zen_generation_id)
                    if zen_generation == 'unknown':
                        fet.psptool.ph.print_warning(f"Unknown {zen_generation_id=}")

                    zen_generation_id = hex(int.from_bytes(directory_body[20:24], 'little'))
                    zen_generation += f' (PSP ID {zen_generation_id})'

                # Resolve to a ROM offset first so aliased addresses share one dedup key
                offset = fet.rom.address_to_offset(offset)
                if offset in directories_by_offset:
                    directories_by_offset[offset].update_zen_generation(fet, zen_generation)
                    found_directories.append(directories_by_offset[offset])
                    continue

                directory = cls.from_offset(fet, offset, zen_generation)
            except Directory.ParseError as e:
                # from_offset already warned about the unknown magic
                if "Empty entry" in str(e):
                    fet.psptool.ph.print_warning(f"Skipping empty directory entry at offset 0x{offset:x}")
                continue
            except Exception as e:
                fet.psptool.ph.print_warning(f"Skipping malformed directory at offset 0x{offset:x}: {e!r}")
                continue

            directories_by_offset[offset] = directory
            fet.rom.entry_count += len(directory.entries)
            found_directories.append(directory)
            todo += reversed([(o, zen_generation, False) for o in directory.secondary_directory_offsets] +
                             [(o, None, True) for o in directory.tertiary_directory_offsets])

        return found_directories

    @classmethod
    def from_offset(cls, fet, rom_offset, zen_generation=None):
        rom_offset = fet.rom.address_to_offset(rom_offset)
        magic = fet.rom.get_bytes(rom_offset, 4)

        if magic == b'\xff\xff\xff\xff' or magic == b'\x00\x00\x00\x00':
            fet.psptool.ph.print_warning(f"Empty FET entry at ROM address 0x{rom_offset:x}")
            raise Directory.ParseError("Empty entry")
        if magic in cls.DIRECTORY_MAGICS:
            return cls(fet.rom, rom_offset, fet.psptool, zen_generation)
        elif magic in BiosDirectory.DIRECTORY_MAGICS:
            return cls.bios_directory_class()(fet.rom, rom_offset, fet.psptool, zen_generation)
        else:
            fet.psptool.ph.print_warning(f"Unknown directory magic {magic} at offset 0x{rom_offset:x}")
            raise Directory.ParseError

    def __init__(self, parent_rom, offset: int, psptool, zen_generation=None):
        # todo: incorporate zen generation from combo dirs
        self.rom = parent_rom
        self.buffer_offset = offset
        self.psptool = psptool
        self.zen_generations = [] if zen_generation is None else [zen_generation]
        self.bios_directory_type = BiosDirectory

        # a directory must parse itself before it knows its size and can initialize its buffer
        self._count = int.from_bytes(self.rom[self.buffer_offset + 8: self.buffer_offset + 12], 'little')
        self.magic = self.rom.get_bytes(self.buffer_offset, 4)
        assert self.magic in self.DIRECTORY_MAGICS
        self.additional_info = self.rom.get_bytes(self.buffer_offset + 12, 4)
        self.header = NestedBuffer(self, self.HEADER_SIZE)
        self.body = NestedBuffer(self, self.ENTRY_SIZE * self.count, buffer_offset=self.HEADER_SIZE)
        self.buffer_size = len(self.header) + len(self.body)
        self.checksum = NestedBuffer(self, 4, 4)

        # now initialize the buffer
        super().__init__(self.rom, self.buffer_size, buffer_offset=self.buffer_offset)

        self.entries: List[DirectoryEntry] = []
        self.files: List[File] = []

        # parse entries
        entry_size = self.ENTRY_CLASS.ENTRY_SIZE
        assert len(self.body) % entry_size == 0, "Directory size not a multiple of entry size!"
        for entry_offset in range(0, len(self.body), entry_size):
            self.entries.append(self.ENTRY_CLASS(self, entry_offset))

        # create/link files
        for entry in self.entries:
            file = self.FILE_CLASS.create_file_if_not_exists(self, entry)
            if file is not None:
                self.files.append(file)

        # check entries for a link to a secondary directory (i.e. a continuation of this directory)
        self.secondary_directory_offsets = []
        self.tertiary_directory_offsets = []

        for entry in self.entries:
            if entry.type in SECONDARY_DIRECTORY_ENTRY_TYPES:
                self.secondary_directory_offsets.append(entry.file_offset())
            elif entry.type in TERTIARY_DIRECTORY_ENTRY_TYPES:
                self.tertiary_directory_offsets.append(entry.file_offset())

        self.verify_checksum()

    def __repr__(self):
        return f'{self.__class__.__name__}(address={hex(self.get_address())}, magic={self.magic}, count={self.count})'

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, value):
        self._count = value

        # update binary representation
        self.header[8:12] = struct.pack('<I', self.count)
        self.update_checksum()

    # 00b: x86 Physical address
    # 01b: Offset from start of the BIOS (flash offset)
    # 10b: Offset from start of directory header
    # 11b: Offset from start of partition
    @property
    def address_mode(self):
        info = struct.unpack('<L', self.additional_info)[0]
        version = (info >> 31) & 1
        if version == 1:
            return (info >> 24) & 3
        else:
            return (info >> 29) & 3

    def verify_checksum(self):
        data = self[0x8:]
        checksum = self.checksum.get_bytes()
        calculated_checksum = fletcher32(data)
        if checksum == calculated_checksum:
            return
        self.psptool.ph.print_warning(f"Could not verify fletcher checksum for directory {self}")

    def update_checksum(self):
        data = self[0x8:]  # checksum is calculated from after the checksum field in the header
        self.checksum.set_bytes(0, 4, fletcher32(data))

    def update_entry_fields(self, file: File, type_, size, offset):
        # 1. Find respective Entry for a given File
        entry = None
        for index, my_entry in enumerate(self.entries):
            # We assume that each directory has at most one entry of a given type
            if my_entry.type == file.type:
                entry = my_entry
                break
        assert(entry is not None)

        # 2. Update fields
        entry.type = type_
        if entry.type not in File.NO_SIZE_ENTRY_TYPES:
            entry.size = size

        # Convert the ROM buffer offset back to the value the entry expects, preserving address mode.
        # This mirrors the inverse of file_offset() in entry.py.
        addr_mode = self.address_mode
        if addr_mode == 2 or addr_mode == 3:
            addr_mode = entry.address_mode

        if addr_mode == 0:
            # x86 physical: preserve upper bits (e.g. 0xFF000000), replace lower bits
            addr_mask = self.rom.addr_mask
            upper_mask = 0xFFFFFFFF ^ addr_mask
            entry.offset = (entry.offset & upper_mask) | (offset & addr_mask)
        elif addr_mode == 1:
            entry.offset = offset
        elif addr_mode == 2 or addr_mode == 3:
            entry.offset = offset - self.buffer_offset
        else:
            entry.offset = offset

        # 3. Update checksum
        self.update_checksum()

    @property
    def zen_generation(self):
        return '\n'.join(self.zen_generations) if self.zen_generations else None

    def update_zen_generation(self, fet, zen_generation):
        if zen_generation is None:
            return
        todo = [self]
        while todo:
            directory = todo.pop()
            if directory is None or zen_generation in directory.zen_generations:
                continue
            directory.zen_generations.append(zen_generation)
            todo += [fet.rom.directories_by_offset.get(offset) for offset in directory.secondary_directory_offsets]


class BiosDirectory(Directory):
    DIRECTORY_MAGICS = [b'$BHD', b'$BL2']

    ENTRY_CLASS = BiosDirectoryEntry
    ENTRY_SIZE = BiosDirectoryEntry.ENTRY_SIZE
    FILE_CLASS = BiosFile
