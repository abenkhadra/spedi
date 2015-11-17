//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.


#include "Fragment.h"
#include <cassert>
namespace disasm {

Fragment::Fragment() :
    m_id{0},
    m_size{0},
    m_start_addr{0}
{ }

Fragment::Fragment(unsigned int id, size_t addr) :
    m_id{id},
    m_start_addr{addr},
    m_size{0}
{ }

bool
Fragment::valid() const {
    return (m_insts.size() > 0);
}

bool
Fragment::isAppendable(const MCInstSmall &inst) const {
    return (inst.addr() == m_start_addr + m_size);
}

size_t
Fragment::size() const {
    return m_insts.size();
}

size_t
Fragment::memSize() const {
    return m_size;
}

void
Fragment::appendInst(const MCInstSmall &inst) {
    assert(isAppendable(inst)
               && "Error trying to append a non-appendable instruction");
    m_insts.push_back(inst);
    m_size += inst.size();
}
}
