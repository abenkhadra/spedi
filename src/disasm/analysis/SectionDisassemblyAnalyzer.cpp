//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Copyright (c) 2016 University of Kaiserslautern.

#include <iostream>
#include "SectionDisassemblyAnalyzer.h"

namespace disasm {

SectionDisassemblyAnalyzer::SectionDisassemblyAnalyzer
    (SectionDisassembly *sec_disasm,
     const std::pair<addr_t, addr_t> &exec_region) :
    m_sec_disassembly{sec_disasm},
    m_exec_start{exec_region.first},
    m_exec_end{exec_region.second} {

}

void SectionDisassemblyAnalyzer::BuildCFG() {

    m_cfg.reserve(m_sec_disassembly->maximalBlockCount());

    auto block_iter = m_sec_disassembly->getMaximalBlocks().begin();
    // handle first MB
    m_cfg.emplace_back(MaximalBlockCFGNode(&(*block_iter)));
    if ((*block_iter).getBranch().isDirect()
        && !isValidCodeAddr((*block_iter).getBranch().getTarget())) {
        // a branch to an address outside of executable code
        (*block_iter).setType(MaximalBlockType::kData);
    }

    std::vector<MaximalBlockCFGNode>::iterator rev_cfg_node_iter;
    // first pass over MBs to mark overlap and invalid targets
    for (++block_iter; // skip the first MB
         block_iter < m_sec_disassembly->getMaximalBlocks().end();
         ++block_iter) {

        m_cfg.emplace_back(MaximalBlockCFGNode(&(*block_iter)));

        if ((*block_iter).getBranch().isDirect()
            && !isValidCodeAddr((*block_iter).getBranch().getTarget())) {
            // a branch to an address outside of executable code
            (*block_iter).setType(MaximalBlockType::kData);
            continue;
        }
        rev_cfg_node_iter = m_cfg.end() - 2;
        // check for overlap MB
        for (auto rev_block_iter = block_iter - 1;
             rev_block_iter
                 > m_sec_disassembly->getMaximalBlocks().begin() - 1;
             --rev_block_iter, --rev_cfg_node_iter) {

            if ((*rev_block_iter).endAddr() <=
                (*block_iter).addrOfFirstInst()) {
                // there is no MB overlap
                break;
            }
//            std::cout << "MaximalBlock: " << (*rev_block_iter).getId()
//                << " Points to: " << (*block_iter).getId() << "\n";
            // set pointer to the overlap block
            (*rev_cfg_node_iter).setOverlapMaximalBlock(&(*block_iter));
        }
    }

    std::vector<MaximalBlockCFGNode>::iterator cfg_node_iter = m_cfg.begin();
    // second pass for setting successors and predecessors to each MB
    for (block_iter = m_sec_disassembly->getMaximalBlocks().begin();
         block_iter < m_sec_disassembly->getMaximalBlocks().end();
         ++block_iter, ++cfg_node_iter) {

        if ((*block_iter).isData()) {
            continue;
        }
        if ((*block_iter).getBranch().isConditional()) {
            auto succ = getDirectSuccessor((*cfg_node_iter));
            if (succ != nullptr) {
                (*cfg_node_iter).setDirectSuccessor(succ);
                getCFGNodeOf(succ)->addPredecessor(&(*block_iter),
                                                   (*block_iter).endAddr());
            } else {
                // a conditional branch without a direct successor is data
                (*block_iter).setType(MaximalBlockType::kData);
            }
        }
        if ((*block_iter).getBranch().isDirect()) {
            auto branch_target = (*block_iter).getBranch().getTarget();
            if (!m_sec_disassembly->isWithinSectionAddressSpace(branch_target)) {
                // a valid direct branch can happen to an executable section
                // other than this section.
                continue;
            }
            auto succ =
                getRemoteSuccessor((*cfg_node_iter), branch_target);
            if (succ != nullptr) {
                (*cfg_node_iter).setRemoteSuccessor(succ);
                getCFGNodeOf(succ)->addPredecessor(&(*block_iter),
                                                   branch_target);
            } else {
                // a direct branch that doesn't target an MB is data
                (*block_iter).setType(MaximalBlockType::kData);
            }
        }
    }
    m_valid = true;
}

bool SectionDisassemblyAnalyzer::isValidCodeAddr(addr_t addr) const {
    // XXX: validity should consider alignment of the address
    return (m_exec_start <= addr) && (addr < m_exec_end);
}

MaximalBlock *SectionDisassemblyAnalyzer::getDirectSuccessor
    (const MaximalBlockCFGNode &block_node) const {

    auto current_block = block_node.getMaximalBlock();
    if (m_sec_disassembly->isLast(current_block)) {
        return nullptr;
    }
    auto direct_succ =
        m_sec_disassembly->ptrToMaximalBlockAt(current_block->getId() + 1);
    if (direct_succ->isInstructionAddress(current_block->endAddr())) {
        return direct_succ;
    }
    auto overlap_block =
        m_cfg[current_block->getId() + 1].getOverlapMaximalBlock();
    if (overlap_block != nullptr &&
        overlap_block->isInstructionAddress(current_block->endAddr())) {
        return overlap_block;
    }
    return nullptr;
}

MaximalBlock *SectionDisassemblyAnalyzer::getRemoteSuccessor
    (const MaximalBlockCFGNode &block, addr_t target) const {

    // binary search to find the remote MB that is targeted.
    if (target < m_exec_start || target > m_exec_end) {
        return nullptr;
    }
    size_t first = 0;
    size_t last = m_sec_disassembly->maximalBlockCount() - 1;
    size_t middle = (first + last) / 2;
    while (middle > first) {
        if (target <
            m_sec_disassembly->maximalBlockAt(middle).addrOfLastInst()) {
            last = middle;
        } else {
            first = middle;
        }
        middle = (first + last) / 2;
    }

    if (m_sec_disassembly->maximalBlockAt(last).isInstructionAddress(target)) {
        return m_sec_disassembly->ptrToMaximalBlockAt(last);
    }
    if (m_sec_disassembly->maximalBlockAt(first).isInstructionAddress(target)) {
        return m_sec_disassembly->ptrToMaximalBlockAt(first);
    }

    // Handle overlap MBs.
    auto overlap_block = m_cfg[last].getOverlapMaximalBlock();
    if (overlap_block != nullptr &&
        overlap_block->isInstructionAddress(target)) {
        return overlap_block;
    }
    return nullptr;
}

MaximalBlockCFGNode *SectionDisassemblyAnalyzer::getCFGNodeOf
    (const MaximalBlock *max_block) {
    return &(*(m_cfg.begin() + max_block->getId()));
}
}