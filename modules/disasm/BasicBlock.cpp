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

namespace disasm{

BasicBlock::BasicBlock(unsigned int id) :
    m_id{id},
    m_br_type{BranchInstType::kUnknown},
    m_br_target{0}
{ }

const BranchInstType &BasicBlock::branchType() const {
    return m_br_type;
}

addr_t BasicBlock::branchTarget() const {
    return m_br_target;
}

bool BasicBlock::valid() const {
    return (m_br_type != BranchInstType::kUnknown) ;
}

unsigned int BasicBlock::id() const {
    return m_id;
}

const std::vector<unsigned int>&
BasicBlock::getFragmentIds() const {
    return m_frag_ids;
}

size_t BasicBlock::size() const {
    return m_frag_ids.size();
}
}
