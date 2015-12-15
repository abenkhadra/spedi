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
#include <capstone/capstone.h>

namespace disasm {

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
MaximalBlockBuilder::createBasicBlockWith(const cs_insn *inst) {
    m_bblocks.emplace_back(BasicBlock(m_bb_idx));
    // link basic block to fragment
    m_bblocks.back().append(inst);
    m_insts.emplace_back(MCInstSmall(inst));
    m_last_addr = inst->address + inst->size;
    m_bb_idx++;
}

void
MaximalBlockBuilder::createValidBasicBlockWith(const cs_insn *inst) {
    createBasicBlockWith(inst);
    m_bblocks.back().m_valid = true;
    setBranch(inst);
}

MaximalBlock MaximalBlockBuilder::build() {
    MaximalBlock result{m_max_block_idx, m_branch};
    m_max_block_idx++;

    if (!m_buildable)
        // return an invalid maximal block!
        return result;
    // copy valid BBs to result
    unsigned idx = 0;
    std::vector<BasicBlock> invalid_blocks;
    std::vector<MCInstSmall> invalid_insts;

    for (const BasicBlock &bblock : m_bblocks) {
        if (bblock.valid()) {
            result.m_bblocks.push_back(bblock);
            result.m_bblocks.back().m_id = idx;
            idx++;
        } else {
            invalid_blocks.push_back(bblock);
        }
    }

    auto inst_count = m_insts.size();
    bool valid_insts[inst_count];
    std::memset(valid_insts, 0, inst_count * sizeof(bool));

    // check all valid instruction in the maximal block.
    // an instruction is valid if it belongs to at least one valid block.
    for (unsigned i = 0; i < inst_count; ++i) {
        for (auto &bblock : m_bblocks) {
            if (!bblock.valid()) continue;
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
        } else {
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
        return true;
    }

    int overlap_distance = 0;
    std::vector<BasicBlock> overlap_blocks;
    for (auto &bblock : m_bblocks) {
        // XXX for variable length RISC an overlap can happen only at last
        //  two bytes.
        overlap_distance = abs(static_cast<int>(bblock.startAddr()
            + bblock.size() - m_last_addr));
        if (overlap_distance == 2 || overlap_distance == 0) {
            // XXX There can be multiple overlap blocks that but all of them
            // should end with the same instruction
            overlap_blocks.push_back(bblock);
            overlap_blocks.back().m_id = m_bb_idx;
            m_bb_idx++;
        }
    }

    if (overlap_blocks.size() == 0) {
        m_bblocks.clear();
        m_insts.clear();
        return true;
    }

    if (m_bblocks.size() == 1) {
        // there is only one basic block which happens to be also overlapping.
        m_bblocks.back().m_id = 0;
        m_last_addr = m_bblocks.back().startAddr() + m_bblocks.back().size();
        return false;
    }
    // there are multiple invalid basic blocks. Keep only insts of overlap block.
    std::vector<MCInstSmall> overlap_insts;

    auto inst_count = m_insts.size();
    bool valid_insts[inst_count];
    std::memset(valid_insts, 0, inst_count * sizeof(bool));

    // check all valid instruction in the maximal block.
    // an instruction is valid if it belongs to at least one valid block.
    for (unsigned i = 0; i < inst_count; ++i) {
        for (auto &bblock : overlap_blocks) {
            if (valid_insts[i]) break;
            for (auto addr : bblock.m_insts_addr) {
                if (m_insts[i].addr() == addr) {
                    valid_insts[i] = true;
                    overlap_insts.push_back(m_insts[i]);
                    break;
                }
            }
        }
    }
    assert(overlap_insts.size() > 0 && "Empty overlap instructions detected!!");
    m_insts.swap(overlap_insts);
    m_bblocks.swap(overlap_blocks);
    // all overlap block would end at the same address in Variable Length Risc
    m_last_addr = m_bblocks.back().startAddr() + m_bblocks.back().size();
    return false;
}

void MaximalBlockBuilder::append(const cs_insn *inst) {

    if (m_bblocks.size() == 0) {
        createBasicBlockWith(inst);
        return;
    }
    // get all appendable BBs
    bool appendable = false;
    for (auto &bblock : m_bblocks) {
        if (bblock.isAppendableBy(inst)) {
            bblock.append(inst);
            appendable = true;
        }
    }

    if (appendable) {
        m_insts.emplace_back(MCInstSmall(inst));
        m_last_addr += inst->size;
    } else {
        createBasicBlockWith(inst);
    }
}

void MaximalBlockBuilder::appendBranch(const cs_insn *inst) {
    m_buildable = true;

    if (m_bblocks.size() == 0) {
        createValidBasicBlockWith(inst);
        return;
    }
    bool found_appendable = false;
    // get all appendable BBs
    for (auto &bblock : m_bblocks) {
        if (bblock.isAppendableBy(inst)) {
            bblock.append(inst);
            // a BB that ends with a branch is valid
            bblock.m_valid = true;
            found_appendable = true;
        }
    }

    if (found_appendable) {
        m_insts.emplace_back(MCInstSmall(inst));
        m_last_addr += inst->size;
    } else {
        createValidBasicBlockWith(inst);
    }
    setBranch(inst);
}

void MaximalBlockBuilder::setBranch(const cs_insn *inst) {
    cs_detail *detail = inst->detail;
    for (int i = 0; i < detail->arm.op_count; ++i) {
        if (detail->arm.operands[i].type == ARM_OP_IMM) {
            m_branch.m_direct = true;
            m_branch.m_condition = detail->arm.cc;
            m_branch.m_target = detail->arm.operands[i].imm;
            break;
        } else if (detail->arm.operands[i].type == ARM_OP_MEM) {
            m_branch.m_direct = false;
            m_branch.m_condition = detail->arm.cc;
            m_branch.m_operand = detail->arm.operands[i].mem;
            break;
        }
    }
}
}
