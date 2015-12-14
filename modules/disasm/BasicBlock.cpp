//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "BasicBlock.h"
#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <capstone/capstone.h>

namespace disasm{

BasicBlock::BasicBlock(unsigned int id) :
    m_id{id},
    m_mem_size{0}
{ }


bool BasicBlock::valid() const {
    return (m_insts_addr.size() > 0) ;
}

unsigned int BasicBlock::id() const {
    return m_id;
}

const size_t &BasicBlock::size() const {
    return m_mem_size;
}

bool BasicBlock::isAppendableBy(const cs_insn *inst) const {
    return (inst->address == startAddr() + m_mem_size);
}

bool BasicBlock::isAppendableAt(const addr_t addr) const {
    return (addr == startAddr() + m_mem_size);
}

size_t BasicBlock::instCount() const {
    return m_insts_addr.size();
}

addr_t BasicBlock::startAddr() const {
    return m_insts_addr[0];
}

void BasicBlock::append(const cs_insn *inst) {
    m_insts_addr.push_back(inst->address);
    m_mem_size += inst->size;
}
}
