//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

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
    m_insts.emplace_back(MCInst(inst));
    m_end_addr = inst->address + inst->size;
    m_bb_idx++;
}

void
MaximalBlockBuilder::createValidBasicBlockWith(const cs_insn *inst) {
    createBasicBlockWith(inst);
    m_bblocks.back().m_valid = true;
    setBranch(inst);
}

MaximalBlock MaximalBlockBuilder::buildResultDirectlyAndReset() {
    MaximalBlock result{m_max_block_idx, m_branch};
    // one BB & buildable then put in the result
    result.m_bblocks.swap(m_bblocks);
    result.m_insts.swap(m_insts);
    result.m_end_addr = result.m_insts.back().addr()
        + result.m_insts.back().size();
    m_bb_idx = 0;
    m_end_addr = 0;
    m_buildable = false;
    m_max_block_idx++;
    return result;
}

MaximalBlock MaximalBlockBuilder::buildResultFromValidBasicBlocks
    (const std::vector<BasicBlock *> &valid_blocks) {
    MaximalBlock result{m_max_block_idx, m_branch};
    for (auto block : valid_blocks) {
        result.m_bblocks.push_back(*block);
    }
    // move only valid instructions to result
    for (auto inst_iter = m_insts.cbegin();
         inst_iter < m_insts.cend(); ++inst_iter) {
        bool inst_valid = false;
        for (auto valid_block_iter = valid_blocks.cbegin();
             valid_block_iter < valid_blocks.cend() && !inst_valid;
             ++valid_block_iter) {
            for (auto addr :
                (*valid_block_iter)->getInstructionAddresses()) {
                if ((*inst_iter).addr() == addr) {
                    result.m_insts.push_back(*inst_iter);
                    inst_valid = true;
                    break;
                }
            }
        }
    }
    result.m_end_addr = result.m_insts.back().addr()
        + result.m_insts.back().size();
    return result;
}
MaximalBlock MaximalBlockBuilder::build() {
    if (!m_buildable) {
        //  return an invalid maximal block!
        m_max_block_idx++;
        return disasm::MaximalBlock();
    }
    if (m_bblocks.size() == 1) {
        return buildResultDirectlyAndReset();
    }
    // classify BBs to valid and overlap the rest (if found) should be discarded
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
        if (valid_blocks.size() == m_bblocks.size()) {
            // all basic blocks are valid and should be moved to result
            return buildResultDirectlyAndReset();
        } else {
            MaximalBlock result = buildResultFromValidBasicBlocks(valid_blocks);
            // move only valid BB to result
            m_bblocks.clear();
            m_insts.clear();
            m_bb_idx = 0;
            m_end_addr = 0;
            m_buildable = false;
            m_max_block_idx++;
            return result;
        }
    }
    // Case of BB overlap then MB should maintain overlap BBs and their instructions.
    MaximalBlock result = buildResultFromValidBasicBlocks(valid_blocks);
    std::vector<MCInst> insts_buffer;
    std::vector<BasicBlock> bb_buffer;
    // copy all overlap blocks
    for (auto block_iter = overlap_blocks.cbegin();
         block_iter < overlap_blocks.cend(); ++block_iter) {
        bb_buffer.push_back(*(*block_iter));
    }
    // move only overlap instructions to inst buffer
    for (auto inst_iter = m_insts.cbegin();
         inst_iter < m_insts.cend(); ++inst_iter) {
        bool is_overlap_inst = false;
        for (auto overlap_block_iter = overlap_blocks.cbegin();
             overlap_block_iter < overlap_blocks.cend() && !is_overlap_inst;
             ++overlap_block_iter) {
            for (auto addr :
                (*overlap_block_iter)->getInstructionAddresses()) {
                if ((*inst_iter).addr() == addr) {
                    insts_buffer.push_back(*inst_iter);
                    is_overlap_inst = true;
                    break;
                }
            }
        }
    }
    // keep overlap instructions and blocks
    m_insts.swap(insts_buffer);
    m_bblocks.swap(bb_buffer);
    m_end_addr = m_insts.back().addr() + m_insts.back().size();
    assert(result.m_bblocks.size() > 0
               && "No Basic Blocks in Maximal Block!!");
    assert(result.m_insts.size() > 0
               && "No Instructions in Maximal Block!!");
    m_bb_idx = overlap_blocks.size();
    m_buildable = false;
    m_max_block_idx++;
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
        m_insts.emplace_back(MCInst(inst));
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
        m_insts.emplace_back(MCInst(inst));
        m_end_addr = inst->address + inst->size;
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

}
