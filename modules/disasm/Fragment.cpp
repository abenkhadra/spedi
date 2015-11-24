//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "Fragment.h"

namespace disasm {

Fragment::Fragment() :
    m_id{0},
    m_size{0} { }

Fragment::Fragment(unsigned int id, size_t addr) :
    m_id{id},
    m_size{0} { }

Fragment::Fragment(unsigned int id, const MCInstSmall &inst) :
    m_id{id},
    m_size{inst.size()} {
    m_insts.push_back(inst);
}

bool
Fragment::valid() const {
    return (m_insts.size() > 0);
}

bool
Fragment::isAppendable(const MCInstSmall &inst) const {
    return (inst.addr() == startAddr() + m_size);
}

bool
Fragment::isAppendableAt(const addr_t addr) const {
    return (addr == startAddr() + m_size);
}

size_t
Fragment::size() const {
    return m_insts.size();
}

size_t
Fragment::memSize() const {
    return m_size;
}

addr_t
Fragment::startAddr() const {
    return m_insts[0].addr();
}
unsigned int Fragment::id() const {
    return m_id;
}
}
