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
        disasm/ElfDisassembler.cpp disasm/ElfDisassembler.h
        disasm/RawInstWrapper.cpp disasm/RawInstWrapper.h
        disasm/ElfData.h
        disasm/MCInst.cpp disasm/MCInst.h
        disasm/Fragment.cpp disasm/Fragment.h
        disasm/BasicBlock.cpp disasm/BasicBlock.h
        disasm/MaximalBlock.cpp disasm/MaximalBlock.h
        disasm/common.h
        disasm/SectionDisassembly.cpp disasm/SectionDisassembly.h
        disasm/MCParser.cpp disasm/MCParser.h
        disasm/MaximalBlockBuilder.cpp disasm/MaximalBlockBuilder.h
        disasm/RawInstAnalyzer.cpp disasm/RawInstAnalyzer.h
        disasm/BranchData.cpp disasm/BranchData.h
        disasm/analysis/MaximalBlockCFGNode.cpp
        disasm/analysis/MaximalBlockCFGNode.h
        disasm/analysis/SectionDisassemblyAnalyzer.cpp
        disasm/analysis/SectionDisassemblyAnalyzer.h
        disasm/analysis/DisassemblyCFG.cpp
        disasm/analysis/DisassemblyCFG.h
        disasm/analysis/MCInstAnalyzer.cpp disasm/analysis/MCInstAnalyzer.h)

#target_compile_options(disasm PRIVATE -fsanitize=address)
add_dependencies(disasm elf++ dwarf++)
