//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once
#include "binutils/elf/elf++.hh"
#include <capstone/capstone.h>

namespace disasm {

enum class ARMCodeSymbol: std::uint8_t {
    kInvalid = 0,
    kThumb = 1,
    kARM = 2,
    kData = 4
};

enum class BasicBlockType: uint8_t {
    kUnknown = 0,
    kThumb = 1,
    kARM = 2,
    kTop = 0xFF
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
    void disassembleCode() const;
    void disassembleCodeSpeculative() const;

    void disassembleSectionbyName(std::string& sec_name) const;
    void print_string_hex(unsigned char *str, size_t len) const;
    bool isSymbolTableAvailable();

    /**
     * Return the type of code at the initial address of executable.
     */
    inline BasicBlockType initCodeType() const;

private:
    void disassembleSectionUsingSymbols(const elf::section &sec) const;
    void initializeCapstone(csh *handle) const;
    void prettyPrintInst(const csh& handle, cs_insn* inst) const;
    std::vector<std::pair<size_t, ARMCodeSymbol>>
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

class BasicBlock{
public:
    BasicBlock();
    virtual ~BasicBlock() = default;

    BasicBlock(BasicBlockType type);
    BasicBlock(BasicBlockType type, void* code, size_t addr);

    BasicBlock(const BasicBlock &src) = default;
    BasicBlock &operator=(const BasicBlock &src) = default;
    BasicBlock(BasicBlock &&src) = default;
    BasicBlock &operator=(BasicBlock &&src) = default;

    BasicBlockType getType() const;
    void setType(const BasicBlockType type);

    void setSize(size_t size);
    size_t getSize() const;

    void setAddr(size_t addr);
    size_t getAddr() const;

    void setCodePtr(void *m_code_ptr);
    void *getCodePtr() const;

private:
    BasicBlockType m_type;
    void* m_code_ptr;
    size_t m_addr;
    size_t m_size;
};
}



