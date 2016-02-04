//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Copyright (c) 2016 University of Kaiserslautern.

#include "SectionDisassemblyAnalyzer.h"
#include "../SectionDisassembly.h"
#include <iostream>
#include <algorithm>
#include <string.h>

namespace disasm {

SectionDisassemblyAnalyzer::SectionDisassemblyAnalyzer
    (SectionDisassembly *sec_disasm,
     const RawInstAnalyzer *analyzer,
     const std::pair<addr_t, addr_t> &exec_region) :
    m_sec_disassembly{sec_disasm},
    m_analyzer{analyzer},
    m_exec_addr_start{exec_region.first},
    m_exec_addr_end{exec_region.second} {
}

void SectionDisassemblyAnalyzer::BuildCFG() {
    if (m_sec_disassembly->maximalBlockCount() == 0) {
        return;
    }
    // work directly with the vector of MaximalBlockCFGNode
    auto &cfg = m_sec_cfg.m_cfg;
    cfg.resize(m_sec_disassembly->maximalBlockCount());
    {
        MaximalBlock *first_maximal_block =
            &(*m_sec_disassembly->getMaximalBlocks().begin());
        // handle first MB
        cfg.front().setMaximalBlock(first_maximal_block);
        if (first_maximal_block->getBranch().isDirect()
            && !isValidCodeAddr(first_maximal_block->getBranch().target())) {
            // a branch to an address outside of executable code
            cfg.front().setType(MaximalBlockType::kData);
        }
    }
    {
        // first pass over MBs to mark overlap and invalid targets skipping first MB
        auto node_iter = cfg.begin() + 1;
        for (
            auto block_iter = m_sec_disassembly->getMaximalBlocks().begin() + 1;
            block_iter < m_sec_disassembly->getMaximalBlocks().end();
            ++block_iter, ++node_iter) {

            (*node_iter).setMaximalBlock(&(*block_iter));
            if ((*block_iter).getBranch().isDirect()
                && !isValidCodeAddr((*block_iter).getBranch().target())) {
                // a branch to an address outside of executable code
                (*node_iter).setType(MaximalBlockType::kData);
                continue;
            }

            // check for overlap MB
            auto rev_cfg_node_iter = (node_iter) - 1;
            for (auto rev_block_iter = block_iter - 1;
                 rev_block_iter
                     > m_sec_disassembly->getMaximalBlocks().begin() - 1;
                 --rev_block_iter, --rev_cfg_node_iter) {

                if ((*rev_block_iter).endAddr() <=
                    (*block_iter).addrOfFirstInst()) {
                    // there is no MB overlap
                    break;
                }
//                std::cout << "MaximalBlock: " << (*rev_block_iter).id()
//                    << " Overlaps with : " << (*block_iter).id() << "\n";
                // set pointer to the overlap block
                (*rev_cfg_node_iter).m_overlap_node = (&(*node_iter));
            }
        }
    }
    {
        // second pass for setting successors and predecessors to each CFGNode
        for (auto node_iter = cfg.begin();
             node_iter < cfg.end(); ++node_iter) {
            if ((*node_iter).isData()) {
                continue;
            }
            auto current_block = (*node_iter).getMaximalBlock();
            if (current_block->getBranch().isConditional()) {
                auto succ = findDirectSuccessor(*node_iter);
                if (succ != nullptr) {
                    (*node_iter).setDirectSuccessor(succ);
                    succ->
                        addPredecessor(&(*node_iter), current_block->endAddr());
//                std::cout << "MaximalBlock: " << (*block_iter).id()
//                    << " Points to: " << (*succ).id() << "\n";
                } else {
                    // a conditional branch without a direct successor is data
                    (*node_iter).setType(MaximalBlockType::kData);
                }
            }
            if (current_block->getBranch().isDirect()) {
                auto branch_target = current_block->getBranch().target();
                if (!m_sec_disassembly->isWithinSectionAddressSpace(
                    branch_target)) {
                    // a valid direct branch can happen to an executable section
                    // other than this section.
                    continue;
                }
                auto succ = findRemoteSuccessor(branch_target);
                if (succ != nullptr) {
                    (*node_iter).setRemoteSuccessor(succ);
                    succ->addPredecessor(&(*node_iter), branch_target);
//                    std::cout << "MaximalBlock: " << (*node_iter).id()
//                        << " Points to: " << (*succ).id() << "\n";
                } else {
                    // a direct branch that doesn't target an MB is data
                    (*node_iter).setType(MaximalBlockType::kData);
                }
            }
        }
    }
    m_sec_cfg.m_valid = true;
}

bool SectionDisassemblyAnalyzer::isValidCodeAddr(addr_t addr) const {
    // XXX: validity should consider alignment of the address
    return (m_exec_addr_start <= addr) && (addr < m_exec_addr_end);
}

MaximalBlockCFGNode *SectionDisassemblyAnalyzer::findDirectSuccessor
    (const MaximalBlockCFGNode &cfg_node) noexcept {
    // no direct successor to last cfg node
    if (cfg_node.id() >= m_sec_cfg.m_cfg.back().id()) {
        return nullptr;
    }
    auto direct_succ =
        &(*(m_sec_cfg.m_cfg.begin() + cfg_node.id() + 1));
    if (direct_succ->getMaximalBlock()->
        isAddressOfInstruction(cfg_node.getMaximalBlock()->endAddr())) {
        return direct_succ;
    }
    auto overlap_node = direct_succ->getOverlapNodePtr();
    if (overlap_node != nullptr && overlap_node->getMaximalBlock()->
        isAddressOfInstruction(cfg_node.getMaximalBlock()->endAddr())) {
        return overlap_node;
    }
    return nullptr;
}

MaximalBlockCFGNode *SectionDisassemblyAnalyzer::findRemoteSuccessor
    (addr_t target) noexcept {

    // binary search to find the remote MB that is targeted.
    if (target < m_exec_addr_start || target > m_exec_addr_end) {
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
        return m_sec_cfg.ptrToNodeAt(last);
    }
    if (m_sec_disassembly->maximalBlockAt(first).isAddressOfInstruction(target)) {
        return m_sec_cfg.ptrToNodeAt(first);
    }
    // Handle overlap MBs.
    auto overlap_node = m_sec_cfg.getNodeAt(last).getOverlapNode();
    if (overlap_node != nullptr &&
        overlap_node->getMaximalBlock()->isAddressOfInstruction(target)) {
        return m_sec_cfg.ptrToNodeAt(overlap_node->id());
    }
    return nullptr;
}

const DisassemblyCFG &SectionDisassemblyAnalyzer::getCFG() const noexcept {
    return m_sec_cfg;
}

void SectionDisassemblyAnalyzer::RefineCFG() {
    if (!m_sec_cfg.isValid()) {
        return;
    }
    for (auto node_iter = m_sec_cfg.m_cfg.begin();
         node_iter < m_sec_cfg.m_cfg.end(); ++node_iter) {
        if ((*node_iter).isData()) {
            continue;
        }
        // resolve overlap between MBs by shrinking the next or converting either to data
        if ((*node_iter).hasOverlapWithOtherNode()
            && !(*node_iter).getOverlapNode()->isData()) {
            if ((*node_iter).getOverlapNode()->getMaximalBlock()->
                coversAddressSpaceOf((*node_iter).getMaximalBlock())) {
                if (m_sec_cfg.calculateNodeWeight(&(*node_iter)) <
                    m_sec_cfg.calculateNodeWeight((*node_iter).getOverlapNode())) {
                    (*node_iter).setType(MaximalBlockType::kData);
                    continue;
                } else {
                    (*node_iter).getOverlapNodePtr()->
                        setType(MaximalBlockType::kData);
                }
            } else {
                // XXX: what if overlapping node consists of only one instruction?
                (*node_iter).getOverlapNodePtr()->
                    setKnownStartAddr((*node_iter).getMaximalBlock()->endAddr());
            }
        }

        if ((*node_iter).getPredecessors().size() > 0) {
            // find maximally valid BB and converts conflicting MBs to data
            SetValidBasicBlock((*node_iter));
        }
    }
}

void SectionDisassemblyAnalyzer::ResolveCFGConflict
    (MaximalBlockCFGNode &node) {
    // Conflicts between predecessors needs to be resolved.
    unsigned assigned_predecessors[node.getPredecessors().size()];
    memset(assigned_predecessors, 0,
           node.getPredecessors().size() * sizeof(unsigned));
    unsigned valid_bb_idx = 0;
    {
        size_t maximum_weight = 0;
        size_t current_weight = 0;
        // find the basic block with maximum weight
        for (unsigned i = 0;
             i < node.getMaximalBlock()->getBasicBlocksCount(); ++i) {
            current_weight = node.getMaximalBlock()->
                getBasicBlockAt(i).instructionCount();
            unsigned j = 0;
            for (auto pred_iter = node.getPredecessors().cbegin();
                 pred_iter < node.getPredecessors().cend(); ++pred_iter, ++j) {
                // basic block weight = calculate predecessor instruction count
                //                      + instruction count of BB
                auto &addrs = node.getMaximalBlock()->
                    getBasicBlockAt(i).InstructionAddresses();
                if (std::find(addrs.begin(), addrs.end(), (*pred_iter).second)
                    != addrs.end()) {
                    assigned_predecessors[j] = i;
                    current_weight += (*pred_iter).first->
                        getMaximalBlock()->instructionsCount();
                }
            }
            if (current_weight > maximum_weight) {
                valid_bb_idx = i;
                maximum_weight = current_weight;
            }
        }
    }
    node.m_valid_basic_block_ptr =
        node.m_max_block->ptrToBasicBlockAt(valid_bb_idx);
    unsigned j = 0;
    for (auto pred_iter = node.getPredecessors().cbegin();
         pred_iter < node.getPredecessors().cend(); ++pred_iter, ++j) {
        if (assigned_predecessors[j] != valid_bb_idx) {
            auto &addrs = node.getMaximalBlock()->
                getBasicBlockAt(valid_bb_idx).InstructionAddresses();
            if (!std::binary_search(addrs.begin(),
                                    addrs.end(),
                                    (*pred_iter).second)) {
                // set predecessor to data
                printf("CONFLICT: Invalidating %u predecessor of %u\n",
                       (*pred_iter).first->id(),
                       node.id());
                (*pred_iter).first->setType(MaximalBlockType::kData);
            }
        }
    }
}

void SectionDisassemblyAnalyzer::SetValidBasicBlock(MaximalBlockCFGNode &node) {

    if (node.getMaximalBlock()->getBasicBlocksCount() == 1) {
        // In case there is only one basic block then its the valid one
        node.m_valid_basic_block_ptr = node.m_max_block->ptrToBasicBlockAt(0);
        return;
    }
    // The common case where all branches target the same basic block
    for (auto &block :node.getMaximalBlock()->getBasicBlocks()) {
        unsigned target_count = 0;
        for (auto pred_iter = node.getPredecessors().cbegin();
             pred_iter < node.getPredecessors().cend(); ++pred_iter) {
            for (addr_t addr : block.InstructionAddresses()) {
                if ((*pred_iter).second == addr) {
                    target_count++;
                }
            }
        }
        // XXX: what if more than one BB satisfies all targets?
        // currently we choose the earlier (bigger)
        if (target_count == node.getPredecessors().size()) {
            node.m_valid_basic_block_ptr = node.m_max_block->
                ptrToBasicBlockAt(block.id());
            return;
        }
    }
    // No basic block satisfies all targets then conflicts should be resolved
    ResolveCFGConflict(node);
}
}
