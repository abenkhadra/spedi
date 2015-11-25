//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "MaximalBlock.h"
#include <cassert>

namespace disasm {

size_t
MaximalBlock::getBasicBlockSize(const unsigned int bb_id) const {
    assert(bb_id <= m_bblocks.size()
               && "Invalid Basic Block Id!!");
    return m_bblocks[bb_id].size();
}

size_t
MaximalBlock::getBasicBlockMemSize(const unsigned int bb_id) const {
    assert(bb_id <= m_bblocks.size()
               && "Invalid Basic Block Id!!");
    size_t result = 0;
    for(auto index:m_bblocks[bb_id].m_frag_ids){
        result += m_frags[index].memSize();
    }
    return result;
}

bool MaximalBlock::valid() const {
    if (m_bblocks.size() == 0)
        return false;

    for(const BasicBlock& block: m_bblocks)
        if (!block.valid())
            return false;

    return true;
}

addr_t MaximalBlock::getStartAddr() const {
    if (m_frags.size() == 0)
        return 0;
    else
        return m_frags[0].startAddr();
}

void MaximalBlock::setType(const MaxBlockType type) {
    m_type = type;
    if (m_type == MaxBlockType::kData) {
        m_frags.clear();
        m_bblocks.clear();
    }
}

const BasicBlock&
MaximalBlock::getBasicBlock(const unsigned int bb_id) const {
    return m_bblocks[bb_id];
}
}
