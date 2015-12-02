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
    return m_bblocks[bb_id].size();
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
        return m_insts[0].addr();
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

unsigned MaximalBlock::getInstructionCount() const {
    return static_cast<unsigned> (m_insts.size());
}

const std::vector<MCInstSmall*>
MaximalBlock::getInstructions(BasicBlock &bblock){
    std::vector<MCInstSmall*> result;
    std::vector<MCInstSmall>::iterator iter;
    std::vector<MCInstSmall>::iterator current = m_insts.begin();
//    current = m_insts.begin();

    for (auto addr : bblock.m_insts_addr) {
        for (iter = current; iter < m_insts.end(); ++iter) {
            if ((*iter).addr() == addr) {
                result.push_back(&(*iter));
                current = iter;
                break;
            }
        }
    }
    return result;
}
}
