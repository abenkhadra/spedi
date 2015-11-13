//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.


#include "Fragment.h"
namespace disasm {
Fragment::Fragment() : m_append_addr{0} {

}

Fragment::Fragment(size_t addr) : m_append_addr{addr} {

}

bool
Fragment::Valid() const {
    return (m_insts.size() > 0);
}

bool
Fragment::isAppendable(const BCInstSmall &inst) const {
    return (inst.getAddr() == m_append_addr);
}

size_t
Fragment::Size() const {
    return m_insts.size();
}

size_t
Fragment::MemSize() const {
    if (m_insts.size() > 0)
        m_append_addr - m_insts[0].getAddr();
    else return 0;
}

void
Fragment::appendInst(const BCInstSmall &inst) {
    if (!isAppendable(inst))
        m_insts.push_back(inst);
}
}
