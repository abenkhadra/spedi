//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Copyright (c) 2016 University of Kaiserslautern.

#include "SectionDisassemblyAnalyzer.h"
#include <iostream>

namespace disasm {

SectionDisassemblyAnalyzer::SectionDisassemblyAnalyzer
    (SectionDisassembly *sec_disasm,
     const std::pair<addr_t, addr_t> &exec_region) :
    m_sec_disassembly{sec_disasm},
    m_exec_start{exec_region.first},
    m_exec_end{exec_region.second} {

}

void SectionDisassemblyAnalyzer::BuildCFG() {
    auto &cfg = m_sec_cfg.m_cfg;
    cfg.reserve(m_sec_disassembly->maximalBlockCount());

    {
        auto block_iter = m_sec_disassembly->getMaximalBlocks().begin();
        // handle first MB
        cfg.emplace_back(MaximalBlockCFGNode(&(*block_iter)));
        if ((*block_iter).getBranch().isDirect()
            && !isValidCodeAddr((*block_iter).getBranch().target())) {
            // a branch to an address outside of executable code
            cfg.back().setType(MaximalBlockType::kData);
        }
    }
    // first pass over MBs to mark overlap and invalid targets skipping first MB
    for (auto block_iter = m_sec_disassembly->getMaximalBlocks().begin() + 1;
         block_iter < m_sec_disassembly->getMaximalBlocks().end();
         ++block_iter) {

        cfg.emplace_back(MaximalBlockCFGNode(&(*block_iter)));
        if ((*block_iter).getBranch().isDirect()
            && !isValidCodeAddr((*block_iter).getBranch().target())) {
            // a branch to an address outside of executable code
            cfg.back().setType(MaximalBlockType::kData);
            continue;
        }
        auto rev_cfg_node_iter = cfg.end() - 2;
        // check for overlap MB
        for (auto rev_block_iter = block_iter - 1;
             rev_block_iter > m_sec_disassembly->getMaximalBlocks().begin() - 1;
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


    // second pass for setting successors and predecessors to each MB
    for (auto cfg_node_iter = cfg.begin();
         cfg_node_iter < cfg.end(); ++cfg_node_iter) {

        if ((*cfg_node_iter).isData()) {
            continue;
        }
        MaximalBlock *current_block = (*cfg_node_iter).m_current;
        if (current_block->getBranch().isConditional()) {
            auto succ = getDirectSuccessor((*cfg_node_iter));
            if (succ != nullptr) {
                (*cfg_node_iter).setDirectSuccessor(succ);
                m_sec_cfg.getCFGNodeOf(succ)->
                    addPredecessor(current_block, current_block->endAddr());
//                std::cout << "MaximalBlock: " << (*block_iter).getId()
//                    << " Points to: " << (*succ).getId() << "\n";
            } else {
                // a conditional branch without a direct successor is data
                (*cfg_node_iter).setType(MaximalBlockType::kData);
            }
        }
        if (current_block->getBranch().isDirect()) {
            auto branch_target = current_block->getBranch().target();
            if (!m_sec_disassembly->isWithinSectionAddressSpace(branch_target)) {
                // a valid direct branch can happen to an executable section
                // other than this section.
                continue;
            }
            auto succ =
                getRemoteSuccessor(branch_target);
            if (succ != nullptr) {
                (*cfg_node_iter).setRemoteSuccessor(succ);
                m_sec_cfg.getCFGNodeOf(succ)->addPredecessor(current_block,
                                                             branch_target);
//                std::cout << "MaximalBlock: " << (*block_iter).getId()
//                    << " Points to: " << (*succ).getId() << "\n";
            } else {
                // a direct branch that doesn't target an MB is data
                (*cfg_node_iter).setType(MaximalBlockType::kData);
            }
        }
    }
    m_sec_cfg.m_valid = true;
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
    if (direct_succ->isAddressOfInstruction(current_block->endAddr())) {
        return direct_succ;
    }
    auto overlap_block =
        m_sec_cfg.nodeAt(current_block->getId() + 1).getOverlapMaximalBlock();
    if (overlap_block != nullptr &&
        overlap_block->isAddressOfInstruction(current_block->endAddr())) {
        return overlap_block;
    }
    return nullptr;
}

MaximalBlock *SectionDisassemblyAnalyzer::getRemoteSuccessor
    (addr_t target) const {

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

    if (m_sec_disassembly->maximalBlockAt(last).isAddressOfInstruction(target)) {
        return m_sec_disassembly->ptrToMaximalBlockAt(last);
    }
    if (m_sec_disassembly->maximalBlockAt(first).isAddressOfInstruction(target)) {
        return m_sec_disassembly->ptrToMaximalBlockAt(first);
    }

    // Handle overlap MBs.
    auto overlap_block = m_sec_cfg.nodeAt(last).getOverlapMaximalBlock();
    if (overlap_block != nullptr &&
        overlap_block->isAddressOfInstruction(target)) {
        return overlap_block;
    }
    return nullptr;
}

const SectionDisassemblyCFG &SectionDisassemblyAnalyzer::getCFG() const {
    return m_sec_cfg;
}
}