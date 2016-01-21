//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#include "MaximalBlock.h"
#include <cassert>

namespace disasm {

size_t
MaximalBlock::getBasicBlockMemSize(const unsigned int bb_id) const {
    assert(bb_id <= m_bblocks.size()
               && "Invalid Basic Block Id!!");
    return m_bblocks[bb_id].size();
}

bool MaximalBlock::isValid() const {
    if (m_bblocks.size() == 0)
        return false;

    for (const BasicBlock &block: m_bblocks)
        if (!block.isValid())
            return false;
    return true;
}

const std::vector<const MCInstSmall *>
MaximalBlock::getInstructionsOf(BasicBlock &bblock) {
    std::vector<const MCInstSmall *> result;

    auto current = bblock.startAddr();
    for (auto iter = m_insts.begin(); iter < m_insts.end(); ++iter) {
        if ((*iter).addr() == current) {
            result.push_back(&(*iter));
            current += (*iter).size();
        }
    }
    return result;
}

const std::vector<addr_t> &
MaximalBlock::getInstructionAddressesOf(const BasicBlock &bblock) const {
    return bblock.m_inst_addrs;
}


addr_t MaximalBlock::getAddrOfFirstInst() const {
    return m_insts[0].addr();
}

void MaximalBlock::setType(const MaximalBlockType type) {
    m_type = type;
    if (m_type == MaximalBlockType::kData) {
        m_bblocks.clear();
    }
}

const BasicBlock &
MaximalBlock::getBasicBlockById(const unsigned int bb_id) const {
    return m_bblocks[bb_id];
}

unsigned int
MaximalBlock::getBasicBlocksCount() const {
    return static_cast<unsigned int>(m_bblocks.size());
}

const std::vector<BasicBlock> &
MaximalBlock::getBasicBlocks() const {
    return m_bblocks;
}

MaximalBlock::MaximalBlock(unsigned id, const BranchData &branch) :
    m_id{id},
    m_type{MaximalBlockType::kMaybe},
    m_branch{branch} {
}

const unsigned &MaximalBlock::getId() const {
    return m_id;
}

unsigned MaximalBlock::instructionsCount() const {
    return static_cast<unsigned> (m_insts.size());
}


const bool MaximalBlock::isWithinAddressSpace(addr_t addr) const {
    return getAddrOfFirstInst() <= addr
        && addr < getEndAddr();
}

addr_t MaximalBlock::getAddrOfLastInst() const {
    return m_insts.back().addr();
}
const std::vector<MCInstSmall> &MaximalBlock::getAllInstructions() const {
    return m_insts;
}
const BranchData &MaximalBlock::getBranch() const {
    return m_branch;
}

MaximalBlock::MaximalBlock() :
    m_type{MaximalBlockType::kMaybe},
    m_start_addr{0} {

}
const addr_t &MaximalBlock::getKnownStartAddr() const {
    return m_start_addr;
}
const MaximalBlockType &MaximalBlock::getType() const {
    return m_type;
}
std::vector<MCInstSmall> MaximalBlock::getKnownInstructions() const {
    std::vector<MCInstSmall> result;
    if (m_start_addr == 0) {
        return result;
    }
    addr_t current = m_start_addr;
    for (auto &inst : m_insts) {
        if (inst.addr() == current) {
            result.push_back(inst);
            current += inst.size();
        }
    }
    return result;
}

addr_t MaximalBlock::getEndAddr() const {
    return (m_insts.back().addr() + m_insts.back().size());
}

bool MaximalBlock::startOverlapsWith(const MaximalBlock &prev_block) const {
    return getAddrOfFirstInst() < prev_block.getEndAddr();
}

bool MaximalBlock::startOverlapsWith(const MaximalBlock *prev_block) const {
    return getAddrOfFirstInst() < prev_block->getEndAddr();;
}

bool MaximalBlock::coversAddressSpaceOf(const MaximalBlock &block) const {
    return getAddrOfFirstInst() < block.getAddrOfFirstInst()
        && getEndAddr() > block.getEndAddr();
}

bool MaximalBlock::coversAddressSpaceOf(const MaximalBlock *block) const {
    return getAddrOfFirstInst() < block->getAddrOfFirstInst()
        && getEndAddr() > block->getEndAddr();
}

bool MaximalBlock::isInstructionAddress(const addr_t inst_addr) const {
    if (inst_addr < getAddrOfFirstInst()) {
        return false;
    }
    for (auto it = m_insts.cbegin(); it < m_insts.cend(); ++it) {
        if ((*it).addr() == inst_addr) {
            return true;
        }
    }
    return false;
}
}
