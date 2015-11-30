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

addr_t MaximalBlock::startAddr() const {
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
MaximalBlock::getBasicBlockById(const unsigned int bb_id) const {
    return m_bblocks[bb_id];
}

unsigned int
MaximalBlock::getBasicBlocksCount() const {
    return static_cast<unsigned int>(m_bblocks.size());
}

unsigned int
MaximalBlock::getFragmentsCount() const {
    return static_cast<unsigned int>(m_frags.size());
}

const std::vector<BasicBlock>&
MaximalBlock::getBasicBlocks() const {
    return m_bblocks;
}

const std::vector<Fragment> &
MaximalBlock::getFragments() const {
    return m_frags;
}

MaximalBlock::MaximalBlock(unsigned int id):
    m_id{id},
    m_type{MaxBlockType::kMaybe} {
}

const unsigned int &MaximalBlock::id() const {
    return m_id;
}
}
