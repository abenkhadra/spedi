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
    m_size{0} { }

bool BasicBlock::isValid() const {
    return m_valid && m_inst_addrs.size() > 0;
}

unsigned BasicBlock::id() const {
    return m_id;
}

const size_t BasicBlock::size() const {
    return m_size;
}

bool BasicBlock::isAppendableBy(const cs_insn *inst) const {
    return (inst->address == endAddr());
}

bool BasicBlock::isAppendableAt(const addr_t addr) const {
    return (addr == endAddr());
}

size_t BasicBlock::instCount() const {
    return (m_inst_addrs.size());
}

addr_t BasicBlock::startAddr() const {
    return m_inst_addrs.front();
}

void BasicBlock::append(const cs_insn *inst) {
    m_inst_addrs.push_back(inst->address);
    m_size += inst->size;
}
addr_t BasicBlock::endAddr() const {
    return m_inst_addrs.front() + m_size;
}
}
