//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "MaximalBlockBuilder.h"
#include <algorithm>
#include <cassert>
#include <array>
#include <cstring>

namespace disasm{

MaximalBlockBuilder::MaximalBlockBuilder() :
    m_buildable{false},
    m_bb_idx{0},
    m_max_block_idx{0},
    m_last_addr{0} {
}

std::vector<unsigned int>
MaximalBlockBuilder::appendableBasicBlocksAt(const addr_t addr) const {
    // XXX: an instruction can be appendable to multiple basic blocks
    // that share the same last fragment.
    std::vector<unsigned int> result;
    for (auto &bblock : m_bblocks) {
        if (bblock.isAppendableAt(addr))
            result.push_back(bblock.id());
    }
    return result;
}

void
MaximalBlockBuilder::createBasicBlockWith(const MCInstSmall &inst) {
    m_bblocks.emplace_back(BasicBlock(m_bb_idx));
    // link basic block to fragment
    m_bblocks.back().append(inst);
    m_insts.push_back(inst);
    m_last_addr = inst.addr() + inst.size();
    m_bb_idx++;
}

void
MaximalBlockBuilder::createBasicBlockWith(
    const MCInstSmall &inst,
    const BranchInstType br_type,
    const addr_t br_target) {

    createBasicBlockWith(inst);
    m_bblocks.back().m_br_type = br_type;
    m_bblocks.back().m_br_target = br_target;
    m_buildable = true;
}

//BasicBlock*
//MaximalBlockBuilder::findBasicBlock(const unsigned int bb_id) const {
//    BasicBlock* result = nullptr;
//    std::vector<BasicBlock>::iterator block;
//    for (block = m_bblocks.begin(); block < m_bblocks.end(); block++) {
//        if (block->id() == bb_id ) {
//            result = &(*block);
//            break;
//        }
//    }
//    return result;
//}

MaximalBlock MaximalBlockBuilder::build() {
    MaximalBlock result{m_max_block_idx};
    m_max_block_idx++;

    if (!m_buildable)
        // return an invalid maximal block!
        return result;
    // copy valid BBs to result
    unsigned idx = 0;
    std::vector<BasicBlock> invalid_blocks;
    std::vector<MCInstSmall> invalid_insts;

    for (const BasicBlock& bblock : m_bblocks) {
        if (bblock.valid()) {
            result.m_bblocks.push_back(bblock);
            result.m_bblocks.back().m_id = idx;
            idx++;
        }else{
            invalid_blocks.push_back(bblock);
        }
    }

    auto inst_count = m_insts.size();
    bool valid_insts[inst_count];
    std::memset(valid_insts, 0, inst_count *sizeof(bool));

    // check all valid instruction in the maximal block
    for (unsigned i = 0; i < inst_count; ++i) {
        for (auto& bblock : m_bblocks) {
            if (valid_insts[i]) break;
            for (auto addr : bblock.m_insts_addr) {
                if (m_insts[i].addr() == addr) {
                    valid_insts[i] = true;
                    break;
                }
            }
        }
    }
    // we do a second iteration in order to maintain the invariant that
    //  m_inst should remain sorted by instruction address.
    for (unsigned j = 0; j < inst_count; ++j) {
        if (valid_insts[j]) {
            result.m_insts.push_back(m_insts[j]);
        }else{
            invalid_insts.push_back(m_insts[j]);
        }
    }
    // MB should maintain invalid basic blocks and their instructions.
    m_insts.swap(invalid_insts);
    m_bblocks.swap(invalid_blocks);
    return result;
}

bool MaximalBlockBuilder::reset() {

    m_buildable = false;
    m_bb_idx = 0;
    if (m_bblocks.size() == 0) {
        assert(m_insts.size() == 0 && "Instructions found without BB!!");
        m_last_addr = 0;
        m_insts.clear();
        return true;
    }
    unsigned id = 0;
    std::vector<BasicBlock> overlap_blocks;
    for (auto& bblock : m_bblocks) {
        // XXX for variable length RISC an overlap can happen only at last
        //  two bytes.
        if (abs(static_cast<int>
                (bblock.startAddr() + bblock.size() - m_last_addr)) == 2) {
            overlap_blocks.push_back(bblock);
            overlap_blocks.back().m_id = m_bb_idx;
            m_bb_idx++;
        }
    }

    if (overlap_blocks.size() == 0) {
        m_last_addr = 0;
        m_bblocks.clear();
        m_insts.clear();
        return true;
    }
    assert(overlap_blocks.size() == 1
               && "Extra overlapping basic blocks detected!!");
    std::vector<MCInstSmall> overlap_insts;
    for (auto& addr: overlap_blocks.back().m_insts_addr) {
        for (auto& inst : overlap_insts) {
            if (inst.addr() == addr) {
                overlap_insts.push_back(inst);
                break;
            }
        }
    }
    assert(overlap_insts.size() > 0 && "Empty overlap instructions detected!!");
    m_insts.swap(overlap_insts);
    m_last_addr = overlap_blocks.back().startAddr()
        + overlap_blocks.back().size();
    return false;
}

void MaximalBlockBuilder::append(const MCInstSmall &inst) {

    if (m_bblocks.size() == 0) {
        createBasicBlockWith(inst);
        return;
    }

    // get all appendable BBs
    bool appendable = false;
    for (auto& bblock : m_bblocks) {
        if (bblock.isAppendableBy(inst)) {
            bblock.append(inst);
            appendable = true;
        }
    }

    if (appendable) {
        m_insts.push_back(inst);
        m_last_addr += inst.size();
    } else {
        createBasicBlockWith(inst);
    }
}

void MaximalBlockBuilder::append(const MCInstSmall &inst,
                                 const BranchInstType br_type,
                                 const addr_t br_target) {
    m_buildable = true;
    if (m_bblocks.size() == 0) {
        createBasicBlockWith(inst);
        return;
    }

    // get all appendable BBs
    bool appendable = false;
    for (auto& bblock : m_bblocks) {
        if (bblock.isAppendableBy(inst)) {
            bblock.append(inst);
            bblock.m_br_type = br_type;
            bblock.m_br_target = br_target;
            appendable = true;
        }
    }

    if (appendable) {
        m_insts.push_back(inst);
        m_last_addr += inst.size();
    } else {
        createBasicBlockWith(inst, br_type, br_target);
    }
}
}
