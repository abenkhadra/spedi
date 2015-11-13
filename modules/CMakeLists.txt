set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

add_library(
        elf++ STATIC
        binutils/elf/mmap_loader.cc
        binutils/elf/to_string.cc
        binutils/elf/elf.cc
)

add_library(
        dwarf++ STATIC
        binutils/dwarf/abbrev.cc
        binutils/dwarf/attrs.cc
        binutils/dwarf/cursor.cc
        binutils/dwarf/die.cc
        binutils/dwarf/die_str_map.cc
        binutils/dwarf/dwarf.cc
        binutils/dwarf/elf.cc
        binutils/dwarf/expr.cc
        binutils/dwarf/line.cc
        binutils/dwarf/rangelist.cc
        binutils/dwarf/value.cc
        binutils/dwarf/to_string.cc
)

add_library(
        disasm STATIC
        disasm/ElfDisassembler.cpp
        disasm/BCInst.cpp
        disasm/ElfData.h
        disasm/BCInstSmall.cpp disasm/BCInstSmall.h
        disasm/Fragment.cpp disasm/Fragment.h
        disasm/BasicBlock.cpp disasm/BasicBlock.h disasm/DominantBlock.cpp disasm/DominantBlock.h disasm/common.h)

add_dependencies(disasm elf++ dwarf++)
