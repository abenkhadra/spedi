//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.


#include "MaximalBlock.h"
#include <cassert>

namespace disasm {

size_t
MaximalBlock::getBasicBlockSize(unsigned int bb_id) {
    assert(bb_id <= m_bblocks.size()
               && "Invalid Basic Block Id!!");
    return m_bblocks[bb_id].size();
}

size_t
MaximalBlock::getBasicBlockMemSize(unsigned int bb_id) {
    assert(bb_id <= m_bblocks.size()
               && "Invalid Basic Block Id!!");
    auto frags = m_bblocks[bb_id].getFragmentIds();
    size_t result = 0;
    for(auto index:frags){
        result += m_frags[index].memSize();
    }
    return result;
}

bool MaximalBlock::valid() {
    if (m_bblocks.size() == 0)
        return false;

    for(BasicBlock& item: m_bblocks)
        if (!item.valid())
            return false;

    return true;
}

addr_t MaximalBlock::getStartAddr() const {
    if (m_frags.size() == 0)
        return 0;
    else
        return m_frags[0].startAddr();
}

void MaximalBlock::setType(MaxBlockType type) {
    m_type = type;
    if (m_type == MaxBlockType::kData) {
        m_frags.clear();
        m_bblocks.clear();
    }
}

}
