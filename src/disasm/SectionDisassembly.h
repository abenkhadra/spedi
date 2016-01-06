//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#pragma once

#include "common.h"
#include "MaximalBlock.h"
#include <string>

namespace elf {
    class section;
}

namespace disasm {
/**
 * SectionDisassembly
 */
class SectionDisassembly {
public:
    /**
     * Construct a SectionDisassembly that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    explicit SectionDisassembly(const elf::section *section);
    virtual ~SectionDisassembly() = default;
    SectionDisassembly(const SectionDisassembly &src) = default;
    SectionDisassembly &operator=(const SectionDisassembly &src) = default;
    SectionDisassembly(SectionDisassembly &&src) = default;

    bool valid() const { return m_valid; }

    const std::string sectionName() const;
    /*
     * start virtual address of section
     */
    const addr_t startAddr() const;
    /*
     * size of section in bytes
     */
    const size_t size() const;
    /*
     * return a pointer to the beginning of bytes of the section
     */
    const uint8_t * data() const;
    /*
     * return a pointer to data at given virtual address
     */
    const uint8_t * dataAt(addr_t addr) const;

    void add(const MaximalBlock &max_block);
    void add(MaximalBlock &&max_block);
    const MaximalBlock& back();


private:
    bool m_valid;
    // section size in bytes, section start address, section ptr, setion name
    elf::section *m_section;
    std::vector<MaximalBlock> m_max_blocks;

};
}
