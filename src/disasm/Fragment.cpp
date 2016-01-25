//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "Fragment.h"

namespace disasm {

Fragment::Fragment() :
    m_id{0} { }

Fragment::Fragment(unsigned int id) :
    m_id{id} { }

bool
Fragment::valid() const {
    return (m_insts.size() > 0);
}

size_t
Fragment::instCount() const {
    return m_insts.size();
}

addr_t
Fragment::startAddr() const {
    return m_insts[0]->addr();
}
unsigned int Fragment::id() const {
    return m_id;
}
}
