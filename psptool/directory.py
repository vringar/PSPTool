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

from .entry import DirectoryEntry, BiosDirectoryEntry, AddressMode
from .utils import NestedBuffer, fletcher32
from .file import File, BiosFile, SECONDARY_DIRECTORY_ENTRY_TYPES, TERTIARY_DIRECTORY_ENTRY_TYPES

from typing import List


class Directory(NestedBuffer):
    DIRECTORY_MAGICS = [b'$PSP', b'$PL2']
    HEADER_SIZE = 4 * 4

    ENTRY_CLASS = DirectoryEntry
    ENTRY_SIZE = DirectoryEntry.ENTRY_SIZE
    FILE_CLASS = File

    ZEN_GENERATION_IDS = {'Zen 1'  : [b'\x00\x09\xBC', b'\x00\x0A\xBC'],
                          'Zen 2'  : [b'\x05\x0B\xBC', b'\x01\x0A\xBC'],
                          'Zen 3'  : [b'\x01\x0C\xBC', b'\x00\x0C\xBC'],
                          'Zen 4'  : [b'\x04\x0D\xBC', b'\x0B\x0D\xBC'],
                          'Zen 4/5': [b'\x03\x0D\xBC', b'\x01\x0D\xBC', b'\x00\x0E\xBC', b'\x0B\x0E\xBC',
                                      b'\x0C\x0E\xBC', b'\x0D\x0E\xBC', b'\x10\x0E\xBC', b'\x11\x0E\xBC']
                         }

    # Empirical mapping from PSP_FW_BOOT_LOADER (entry type 0x01) version
    # major byte to Zen generation. Used as a third detection path for
    # single-generation ROMs (e.g. EPYC server BIOSes) that have neither a
    # 2PSP combo directory nor a tertiary self-tag and so hit neither of the
    # existing zen_generation paths. Source for the majors below: the
    # Test-PSPTool corpus and its bootloader_overview.py table, plus the
    # original issue's empirical scrape across 37 EPYC ROMs.
    BOOTLOADER_VERSION_TO_ZEN = {
        0x07: 'Zen 1',                # Naples server (NaplesPI-SP3): H11DSI, MZ31-AR, S8026
        0x09: 'Zen 1', 0x0A: 'Zen 1', # Naples / Raven Ridge consumer
        0x0B: 'Zen 2', 0x0C: 'Zen 2', # Rome
        0x13: 'Zen 3',                # Milan
        0x29: 'Zen 4',                # Genoa, Siena (Zen 4c shares the major)
        0x3D: 'Zen 5',                # Turin (Bergamo also lands here per the issue)
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
                    directory_body = fet.rom.get_bytes(fet.rom.address_to_offset(offset), 32)

                    # Some ROMs point straight at the L2 directory instead of at a
                    # header holding its offset, so there is nothing to resolve
                    if directory_body[:4] not in cls.DIRECTORY_MAGICS + BiosDirectory.DIRECTORY_MAGICS:
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
                             [(o, zen_generation, True) for o in directory.tertiary_directory_offsets])

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
            entry.file = file
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

    @property
    def address_mode(self) -> AddressMode:
        info = struct.unpack('<L', self.additional_info)[0]
        version = (info >> 31) & 1
        if version == 1:
            return AddressMode((info >> 24) & 3)
        else:
            return AddressMode((info >> 29) & 3)

    def verify_checksum(self):
        data = self[0x8:]
        checksum = self.checksum.get_bytes()
        calculated_checksum = fletcher32(data)
        if checksum == calculated_checksum:
            return
        self.psptool.ph.print_warning(f"Could not verify fletcher checksum for directory {self}")

    def update_checksum(self):
        data = self[0x8:]  # checksum is calculated from after the checksum field in the header
        self.checksum.set_bytes(0, fletcher32(data))

    def update_entry_fields(self, file: File, type_, size, offset):
        # 1. Find respective entry for a given file
        entry = None
        for e in self.entries:
            if e.file is file:
                entry = e
                break
        assert entry is not None, f'No entry for {file} in {self}'

        # 2. Update fields
        entry.type = type_
        if entry.type not in File.NO_SIZE_ENTRY_TYPES:
            entry.size = size

            # file_offset() is affine in entry.offset (within the
            # address mask), so shifting entry.offset by the file's
            # displacement keeps the address mode and upper bits
            # intact, and leaves in-place replacements untouched.
            entry.offset += offset - entry.file_offset()
            assert entry.file_offset() == offset, f'Offset {offset:#x} is not representable by {entry}'

        # 3. Update checksum
        self.update_checksum()

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

    # Per-ROM budgets against crafted images with aliased or overlapping directories
    MAX_DIRECTORIES_PER_ROM = 4096

    MAX_ENTRIES_PER_ROM = 1 << 16

    @property
    def zen_generation(self):
        return '\n'.join(self.zen_generations) if self.zen_generations else None

    @zen_generation.setter
    def zen_generation(self, value):
        self.zen_generations = [] if value is None else [value]


class BiosDirectory(Directory):
    DIRECTORY_MAGICS = [b'$BHD', b'$BL2']

    ENTRY_CLASS = BiosDirectoryEntry
    ENTRY_SIZE = BiosDirectoryEntry.ENTRY_SIZE
    FILE_CLASS = BiosFile
