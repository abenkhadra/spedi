//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#pragma once
#include "SectionDisassembly.h"
#include "binutils/elf/elf++.hh"

namespace disasm {

class ARMCodeSymbolVal {
public:
    static std::string
    kThumb() { return "$t"; }

    static std::string
    kARM() { return "$a"; }

    static std::string
    kData() { return "$d"; }
};

class BasicBlock;

/**
 * ElfDisassembler
 */
class ElfDisassembler {
public:
    /**
     * Construct a Elf Disassembler that is initially not valid.  Calling
     * methods other than valid on this results in undefined behavior.
     */
    ElfDisassembler();

    /**
     * Prepares input file for disassembly.
     * Precondition: file is a valid ELF file.
     */
    explicit ElfDisassembler(const elf::elf& elf_file);
    virtual ~ElfDisassembler() = default;
    ElfDisassembler(const ElfDisassembler &src) = delete;
    ElfDisassembler &operator=(const ElfDisassembler &src) = delete;
    ElfDisassembler(ElfDisassembler &&src) = default;

    bool valid() const { return m_valid; }
    void disassembleCodeUsingSymbols() const;
    void disassembleSectionUsingSymbols(const elf::section &sec) const;

    SectionDisassembly
        disassembleSectionSpeculative(const elf::section &sec) const;
    std::vector<SectionDisassembly> disassembleCodeSpeculative() const;

    void disassembleSectionbyName(std::string sec_name) const;
    void disassembleSectionbyNameSpeculative(std::string sec_name) const;

    bool isSymbolTableAvailable();

    /**
     * Return the type of code at the initial address of executable.
     * needed to distinguish ARM/Thumb.
     */
    ISAType getInitialISAType() const;

private:

    std::vector<std::pair<size_t, ARMCodeSymbolType>>
        getCodeSymbolsForSection(const elf::section &sec) const;

private:
    bool m_valid;
    const elf::elf* m_elf_file;
};
}
