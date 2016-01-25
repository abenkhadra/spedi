//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once
#include "SectionDisassembly.h"
#include "binutils/elf/elf++.hh"
#include "MCInstAnalyzer.h"

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
    explicit ElfDisassembler(const elf::elf &elf_file);
    virtual ~ElfDisassembler() = default;
    ElfDisassembler(const ElfDisassembler &src) = delete;
    ElfDisassembler &operator=(const ElfDisassembler &src) = delete;
    ElfDisassembler(ElfDisassembler &&src) = default;

    bool valid() const { return m_valid; }
    void disassembleCodeUsingSymbols() const;
    SectionDisassembly
        disassembleSectionUsingSymbols(const elf::section &sec) const;

    SectionDisassembly
        disassembleSectionSpeculative(const elf::section &sec) const;
    std::vector<SectionDisassembly> disassembleCodeSpeculative() const;

    SectionDisassembly disassembleSectionbyName(std::string sec_name) const;
    SectionDisassembly
        disassembleSectionbyNameSpeculative(std::string sec_name) const;
    const std::pair<addr_t, addr_t> getExecutableRegion();

    bool isSymbolTableAvailable();

    /**
     * Return the type of code at the initial address of executable.
     * needed to distinguish ARM/Thumb.
     */
    ISAType getInitialMode() const;

    ISAType getElfMachineArch() const;

    void prettyPrintMaximalBlock
        (const MaximalBlock &mblock) const;
    void prettyPrintSectionDisassembly
        (const SectionDisassembly &sec_disasm) const;

private:
    void prettyPrintCapstoneInst
        (const csh &handle, cs_insn *inst, bool details_enabled) const;
    std::vector<std::pair<size_t, ARMCodeSymbolType>>
        getCodeSymbolsOfSection(const elf::section &sec) const;

private:
    bool m_valid;
    mutable MCInstAnalyzer m_analyzer;
    const elf::elf *m_elf_file;
};
}
