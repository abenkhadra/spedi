//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "SectionDisassemblyARM.h"
#include <binutils/elf/elf++.hh>
#include <cassert>

namespace disasm {

SectionDisassemblyARM::SectionDisassemblyARM() : m_valid(false) {
}

SectionDisassemblyARM::SectionDisassemblyARM
    (const elf::section *section) :
    m_valid{false},
    m_isa{ISAType::kThumb},
    m_section{section} {
}

SectionDisassemblyARM::SectionDisassemblyARM
    (const elf::section *section, ISAType isa) :
    m_valid{false},
    m_isa{isa},
    m_section{section} {
}

const std::string
SectionDisassemblyARM::sectionName() const {
    return m_section->get_name();
}

addr_t
SectionDisassemblyARM::startAddr() const {
    return m_section->get_hdr().addr;
}

size_t
SectionDisassemblyARM::sectionSize() const {
    return m_section->size();
}

const uint8_t *
SectionDisassemblyARM::ptrToData() const {
    return static_cast<const uint8_t *>(m_section->data());
}

void SectionDisassemblyARM::add(const MaximalBlock &max_block) {
    assert(m_max_blocks.size() == max_block.id()
               && "invalid index of maximal block");
    m_max_blocks.push_back(max_block);
}

void SectionDisassemblyARM::add(MaximalBlock &&max_block) {
    assert(m_max_blocks.size() == max_block.id()
               && "invalid index of maximal block");
    m_max_blocks.emplace_back(max_block);
}

const MaximalBlock &SectionDisassemblyARM::back() const {
    return m_max_blocks.back();
}

addr_t SectionDisassemblyARM::virtualAddrOf(const uint8_t *ptr) const {
    assert(ptrToData() <= ptr
               && ptr < ptrToData() + sectionSize()
               && "Invalid pointer !!!");
    return startAddr() + (ptr - ptrToData());
}

const uint8_t *SectionDisassemblyARM::physicalAddrOf
    (const addr_t virtual_addr) const {
    assert(startAddr() <= virtual_addr
               && virtual_addr < startAddr() + sectionSize()
               && "Invalid virtual address !!!");
    return ptrToData() + (virtual_addr - startAddr());
}

std::vector<MaximalBlock> &SectionDisassemblyARM::getMaximalBlocks() {
    return m_max_blocks;
}

bool SectionDisassemblyARM::isLast(const MaximalBlock *max_block) const {
    return max_block->id() == m_max_blocks.size() - 1;;
}

bool SectionDisassemblyARM::isFirst(const MaximalBlock *max_block) const {
    return max_block->id() == 0;
}

const MaximalBlock &SectionDisassemblyARM::maximalBlockAt(size_t index) const {
    return m_max_blocks[index];
}

MaximalBlock *SectionDisassemblyARM::ptrToMaximalBlockAt(size_t index) {
    return &(*(m_max_blocks.begin() + index));
}

std::vector<MaximalBlock>::const_iterator SectionDisassemblyARM::cbegin() const {
    return m_max_blocks.cbegin();
}

std::vector<MaximalBlock>::const_iterator SectionDisassemblyARM::cend() const {
    return m_max_blocks.cend();
}

bool SectionDisassemblyARM::isWithinSectionAddressSpace(const addr_t &addr) const {
    return m_section->get_hdr().addr <= addr &&
        addr < m_section->get_hdr().addr + m_section->get_hdr().size;
}

size_t SectionDisassemblyARM::maximalBlockCount() const {
    return m_max_blocks.size();
}

ISAType SectionDisassemblyARM::getISA() const {
    return m_isa;
}

void SectionDisassemblyARM::reserve(size_t maximal_block_count) {
    m_max_blocks.reserve(maximal_block_count);
}
}
