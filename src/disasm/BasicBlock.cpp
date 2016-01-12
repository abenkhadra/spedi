//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#include "BasicBlock.h"
#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <capstone/capstone.h>

namespace disasm {

BasicBlock::BasicBlock(unsigned int id) :
    m_valid{false},
    m_id{id},
    m_inst_count{0} { }

bool BasicBlock::valid() const {
    return m_valid && m_inst_count > 0;
}

unsigned BasicBlock::id() const {
    return m_id;
}

const size_t BasicBlock::size() const {
    return m_append_addr - m_start_addr;
}

bool BasicBlock::isAppendableBy(const cs_insn *inst) const {
    return (inst->address == m_append_addr);
}

bool BasicBlock::isAppendableAt(const addr_t addr) const {
    return (addr == m_append_addr);
}

size_t BasicBlock::instCount() const {
    return m_inst_count;
}

addr_t BasicBlock::startAddr() const {
    return m_start_addr;
}

void BasicBlock::append(const cs_insn *inst) {
    if (m_inst_count == 0) {
        m_start_addr = inst->address;
        m_append_addr = inst->address + inst->size;
    } else {
        m_append_addr += inst->size;
    }
    m_inst_count++;
}
}
