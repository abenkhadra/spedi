//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once

#include "common.h"
#include "MaximalBlock.h"
#include <string>

namespace elf {
class section;
}

namespace disasm {
/**
 * SectionDisassemblyARM
 */
class SectionDisassemblyARM {
public:
    /**
     * Construct a SectionDisassemblyARM that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    SectionDisassemblyARM();
    explicit SectionDisassemblyARM(const elf::section *section);
    SectionDisassemblyARM(const elf::section *section, ISAType isa);
    virtual ~SectionDisassemblyARM() = default;
    SectionDisassemblyARM(const SectionDisassemblyARM &src) = default;
    SectionDisassemblyARM &operator=(const SectionDisassemblyARM &src) = default;
    SectionDisassemblyARM(SectionDisassemblyARM &&src) = default;
    const MaximalBlock &maximalBlockAt(size_t index) const;
    MaximalBlock *ptrToMaximalBlockAt(size_t index);
    std::vector<MaximalBlock>::const_iterator cbegin() const;
    std::vector<MaximalBlock>::const_iterator cend() const;

    bool valid() const { return m_valid; }

    const std::string sectionName() const;
    /*
     * start virtual address of section
     */
    addr_t secStartAddr() const;
    addr_t secEndAddr() const;
    /*
     * size of section in bytes
     */
    size_t sectionSize() const;
    /*
     * return a pointer to the beginning of bytes of the section
     */
    const uint8_t *ptrToData() const;
    size_t maximalBlockCount() const;
    void add(const MaximalBlock &max_block);
    void add(MaximalBlock &&max_block);
    const MaximalBlock &back() const;
    addr_t virtualAddrOf(const uint8_t *ptr) const;
    const uint8_t *physicalAddrOf(const addr_t virtual_addr) const;
    std::vector<MaximalBlock> &getMaximalBlocks();

    bool isLast(const MaximalBlock *max_block) const;
    bool isFirst(const MaximalBlock *max_block) const;
    bool isWithinSectionAddressSpace(const addr_t & addr) const;
    ISAType getISA() const;
    void reserve(size_t maximal_block_count);
    size_t size() const noexcept;

private:
    bool m_valid;
    ISAType m_isa;
    // section size in bytes, section start address, section ptr, setion name
    const elf::section *m_section;
    std::vector<MaximalBlock> m_max_blocks;

};
}
