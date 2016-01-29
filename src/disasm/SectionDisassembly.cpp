//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "SectionDisassembly.h"
#include <binutils/elf/elf++.hh>
#include <cassert>

namespace disasm {

SectionDisassembly::SectionDisassembly(const elf::section *section) :
    m_valid{false},
    m_section{section} {
}

const std::string
SectionDisassembly::sectionName() const {
    return m_section->get_name();
}

addr_t
SectionDisassembly::startAddr() const {
    return m_section->get_hdr().addr;
}

size_t
SectionDisassembly::sectionSize() const {
    return m_section->size();
}

const uint8_t *
SectionDisassembly::data() const {
    return static_cast<const uint8_t *>(m_section->data());
}

void SectionDisassembly::add(const MaximalBlock &max_block) {
    assert(m_max_blocks.size() == max_block.id()
               && "invalid index of maximal block");
    m_max_blocks.push_back(max_block);
}

void SectionDisassembly::add(MaximalBlock &&max_block) {
    assert(m_max_blocks.size() == max_block.id()
               && "invalid index of maximal block");
    m_max_blocks.emplace_back(max_block);
}

const MaximalBlock &
SectionDisassembly::back() const {
    return m_max_blocks.back();
}
addr_t
SectionDisassembly::virtualAddrOf(const uint8_t *ptr) const {
    assert(data() <= ptr
               && ptr < data() + sectionSize()
               && "Invalid pointer !!!");
    return startAddr() + (ptr - data());
}

const uint8_t *
SectionDisassembly::physicalAddrOf(const addr_t virtual_addr) const {
    assert(startAddr() <= virtual_addr
               && virtual_addr < startAddr() + sectionSize()
               && "Invalid virtual address !!!");
    return data() + (virtual_addr - startAddr());
}

std::vector<MaximalBlock> &
SectionDisassembly::getMaximalBlocks() {
    return m_max_blocks;
}
bool SectionDisassembly::isLast(const MaximalBlock *max_block) const {
    return max_block->id() == m_max_blocks.size() - 1;;
}
bool SectionDisassembly::isFirst(const MaximalBlock *max_block) const {
    return max_block->id() == 0;
}

const MaximalBlock &SectionDisassembly::maximalBlockAt(size_t index) const {
    return m_max_blocks[index];
}
MaximalBlock *SectionDisassembly::ptrToMaximalBlockAt(size_t index) {
    return &(*(m_max_blocks.begin() + index));
}
std::vector<MaximalBlock>::const_iterator SectionDisassembly::cbegin() const {
    return m_max_blocks.cbegin();
}
std::vector<MaximalBlock>::const_iterator SectionDisassembly::cend() const {
    return m_max_blocks.cend();
}
bool SectionDisassembly::isWithinSectionAddressSpace(const addr_t &addr) const {
    return m_section->get_hdr().addr <= addr &&
        addr < m_section->get_hdr().addr + m_section->get_hdr().size;
}
size_t SectionDisassembly::maximalBlockCount() const {
    return m_max_blocks.size();
}
}
