//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#include "SectionDisassembly.h"
#include <binutils/elf/elf++.hh>
#include <cassert>

namespace disasm {

SectionDisassembly::SectionDisassembly(const elf::section *section) :
    m_valid{false} {
}

const std::string
SectionDisassembly::sectionName() const {
    return m_section->get_name();
}

const addr_t
SectionDisassembly::startAddr() const {
    return m_section->get_hdr().addr;
}

const size_t
SectionDisassembly::size() const {
    return m_section->size();
}

const uint8_t *
SectionDisassembly::data() const {
    return static_cast<const uint8_t *>(m_section->data());
}

const uint8_t *
SectionDisassembly::dataAt(addr_t addr) const {
    return data() + (addr - startAddr());
}

void SectionDisassembly::add(MaximalBlock &max_block) {
    assert(m_max_blocks.size() == max_block.id()
               && "invalid index of maximal block");
    m_max_blocks.push_back(max_block);
}

void SectionDisassembly::add(MaximalBlock &&max_block) {
    assert(m_max_blocks.size() == max_block.id()
               && "invalid index of maximal block");
    m_max_blocks.push_back(max_block);
}
const MaximalBlock &
SectionDisassembly::back() {
    return m_max_blocks.back();
}
}
