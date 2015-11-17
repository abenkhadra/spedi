//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once
#include "DisassemblyResult.h"
#include "binutils/elf/elf++.hh"
#include <capstone/capstone.h>

namespace disasm {

enum class BasicBlockISAType: unsigned short {
    kUnknown = 0,
    kThumb = 1,
    kARM = 2,
    kTriCore = 3,
    kx86 = 4,
    kMIPS = 5,
    kPPC = 6,
    kSPARC = 7,
    kx86_64 = 8,
};

enum class ARMCodeSymbolType: unsigned short {
    kThumb = 1,
    kARM = 2,
    kData = 4
};

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
    ElfDisassembler(const elf::elf& elf_file);
    virtual ~ElfDisassembler() = default;
    ElfDisassembler(const ElfDisassembler &src) = delete;
    ElfDisassembler &operator=(const ElfDisassembler &src) = delete;
    ElfDisassembler(ElfDisassembler &&src) = default;

    bool valid() const { return m_valid; }
    void disassembleCodeUsingSymbols() const;
    void disassembleSectionUsingSymbols(const elf::section &sec) const;

    void disassembleCodeSpeculative() const;
    void disassembleSectionSpeculative() const;

    void disassembleSectionbyName(std::string& sec_name) const;

    void print_string_hex(unsigned char *str, size_t len) const;
    bool isSymbolTableAvailable();

    /**
     * Return the type of code at the initial address of executable.
     */
    inline BasicBlockISAType initCodeType() const;

private:

    void initializeCapstone(csh *handle) const;
    void prettyPrintInst(const csh& handle, cs_insn* inst) const;
    std::vector<std::pair<size_t, ARMCodeSymbolType>>
        getCodeSymbolsForSection(const elf::section &sec) const;

private:
    bool m_valid;
    const elf::elf* m_elf_file;

    struct CapstoneConfig final{
        public:
        CapstoneConfig():
        arch_type{CS_ARCH_ARM},
            mode{CS_MODE_THUMB},
            details{true}{
        }
        CapstoneConfig(const CapstoneConfig& src) = default;
        CapstoneConfig &operator=(const CapstoneConfig& src) = default;

        cs_arch arch_type;
        cs_mode mode;
        bool details;
    };
    CapstoneConfig m_config;
};

}



