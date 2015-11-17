//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.


#include "BasicBlock.h"
#include <algorithm>
#include <stdexcept>
#include <cassert>

namespace disasm{

BasicBlock::BasicBlock() :
    m_valid{false},
    m_br_type{BranchInstType::kUnknown},
    m_br_target{0}
{ }

bool BasicBlock::ContainsFragment(unsigned short frag_id) {
    auto result = std::find(m_frags.begin(), m_frags.end(), frag_id);
    return (result != std::end(m_frags));
}

unsigned short BasicBlock::firstFragmentId() {
    assert(!m_frags.empty() && "Accessing first fragment id of an empty basic block");
    return m_frags[0];
}

unsigned short BasicBlock::lastFragmentId() {
    return m_frags.back();
}

unsigned short BasicBlock::id() const {
    return m_id;
}

const BranchInstType &BasicBlock::getBranchType() const {
    return m_br_type;
}

addr_t BasicBlock::getBranchTarget() const {
    return m_br_target;
}

}
