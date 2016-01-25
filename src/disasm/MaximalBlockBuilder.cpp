//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

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
    m_end_addr{0} {
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
    m_bblocks.emplace_back(BasicBlock(m_bb_idx, inst));
    m_insts.emplace_back(MCInstSmall(inst));
    m_end_addr = inst->address + inst->size;
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
        //  return an invalid maximal block!
        return result;
    // copy valid BBs to result
    std::vector<BasicBlock *> valid_blocks;
    std::vector<BasicBlock *> overlap_blocks;

    for (auto bblock_iter = m_bblocks.begin();
         bblock_iter < m_bblocks.end(); ++bblock_iter) {
        if ((*bblock_iter).isValid()) {
            valid_blocks.push_back(&(*bblock_iter));
        } else {
            // we keep only potential overlapping BBs
            if (m_end_addr - (*bblock_iter).endAddr() <= 2) {
                overlap_blocks.push_back(&(*bblock_iter));
            }
        }
    }
    // Case of no overlap
    if (overlap_blocks.size() == 0) {
        m_buildable = false;
        m_bb_idx = 0;
        m_end_addr = 0;
        result.m_bblocks.swap(m_bblocks);
        result.m_insts.swap(m_insts);
        result.m_end_addr = result.m_insts.back().addr()
            + result.m_insts.back().size();
        return result;
    }
    // Case of BB overlap then MB should maintain overlap BBs and their instructions.
    if (overlap_blocks.size() > 1) {
        // case of a spurious valid BB overlapping in the middle.
        assert(valid_blocks.size() == 1
                   && "Too many spurious valid blocks");
        assert(valid_blocks.back()->m_inst_addrs.size() == 1
                   && "Too many spurious instructions");
        result.m_insts.push_back(m_insts.back());
        result.m_bblocks.push_back(*(valid_blocks.back()));
        m_insts.pop_back();
        m_bblocks.pop_back();
        m_end_addr = m_insts.back().addr() + m_insts.back().size();
    } else {
        std::vector<MCInstSmall> overlap_insts;
        auto overlap_inst_iter = overlap_blocks.back()->m_inst_addrs.cbegin();
        // Instructions that belong to the overlap BB should be separated from the rest
        for (const auto &inst : m_insts) {
            if (overlap_inst_iter < overlap_blocks.back()->m_inst_addrs.cend() &&
                inst.addr() == (*overlap_inst_iter)) {
                overlap_insts.push_back(inst);
                ++overlap_inst_iter;
            } else {
                result.m_insts.push_back(inst);
            }
        }
        // copy valid BBs to result
        for (auto block_iter = valid_blocks.cbegin();
            block_iter < valid_blocks.cend(); ++block_iter) {
            result.m_bblocks.push_back(*(*block_iter));
        }
        m_end_addr = overlap_blocks.back()->endAddr();
        m_insts.swap(overlap_insts);
        BasicBlock block = *(overlap_blocks.back());
        m_bblocks.clear();
        m_bblocks.push_back(block);
    }

    m_buildable = false;
    m_bb_idx = static_cast<unsigned>(overlap_blocks.size());
    result.m_end_addr = result.m_insts.back().addr()
        + result.m_insts.back().size();
    assert(result.m_bblocks.size() > 0 && "No Basic Blocks in Maximal Block!!");
    assert(result.m_insts.size() > 0 && "No Instructions in Maximal Block!!");
    return result;
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
        m_end_addr += inst->size;
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
        m_end_addr += inst->size;
    } else {
        createValidBasicBlockWith(inst);
    }
    setBranch(inst);
}

void MaximalBlockBuilder::setBranch(const cs_insn *inst) {
    cs_detail *detail = inst->detail;
    m_branch.m_conditional_branch = (inst->detail->arm.cc != ARM_CC_AL);
    if (inst->id == ARM_INS_CBZ || inst->id == ARM_INS_CBNZ) {
        m_branch.m_direct_branch = true;
        m_branch.m_target = static_cast<addr_t>(detail->arm.operands[1].imm);
        return;
    }

    if (inst->detail->arm.op_count == 1
        && inst->detail->arm.operands[0].type == ARM_OP_IMM) {
        m_branch.m_direct_branch = true;
        m_branch.m_target = static_cast<addr_t>(detail->arm.operands[0].imm);
        return;
    }
    m_branch.m_direct_branch = false;
}
bool MaximalBlockBuilder::isCleanReset() {
    return !m_buildable && m_bblocks.size() == 0;
}
const std::vector<addr_t>
MaximalBlockBuilder::getInstructionAddrsOf(const BasicBlock &bblock) const {
    return bblock.m_inst_addrs;
}

addr_t MaximalBlockBuilder::endAddr() const {
    return m_end_addr;
}
}
