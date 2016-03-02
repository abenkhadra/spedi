//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Copyright (c) 2016 University of Kaiserslautern.

#include "SectionDisassemblyAnalyzerARM.h"
#include "disasm/SectionDisassemblyARM.h"
#include <iostream>
#include <algorithm>

namespace disasm {

SectionDisassemblyAnalyzerARM::SectionDisassemblyAnalyzerARM
    (SectionDisassemblyARM *sec_disasm,
     const std::pair<addr_t, addr_t> &exec_region) :
    m_sec_disassembly{sec_disasm},
    m_analyzer{sec_disasm->getISA()},
    m_exec_addr_start{exec_region.first},
    m_exec_addr_end{exec_region.second} {
}

size_t SectionDisassemblyAnalyzerARM::calculateBasicBlockWeight
    (const CFGNode &node, const BasicBlock &basic_block) const noexcept {
    unsigned pred_weight = 0;
    for (auto pred_iter = node.getDirectPredecessors().cbegin();
         pred_iter < node.getDirectPredecessors().cend(); ++pred_iter) {
        if (!(*pred_iter).first->isData()) {
            pred_weight +=
                (*pred_iter).first->getMaximalBlock()->instructionsCount();
        }
    }
    return pred_weight + basic_block.instructionCount();
}

size_t SectionDisassemblyAnalyzerARM::calculateNodeWeight
    (const CFGNode *node) const noexcept {
    if (node->isData()) {
        return 0;
    }
    unsigned pred_weight = 0;
    for (auto pred_iter = node->getDirectPredecessors().cbegin();
         pred_iter < node->getDirectPredecessors().cend(); ++pred_iter) {
        pred_weight +=
            (*pred_iter).first->getMaximalBlock()->instructionsCount();
    }
    return node->getMaximalBlock()->instructionsCount() + pred_weight;
}

void SectionDisassemblyAnalyzerARM::buildCFG() {
    if (m_sec_disassembly->maximalBlockCount() == 0) {
        return;
    }
    // work directly with the vector of CFGNode
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
            cfg.front().setToDataAndInvalidatePredecessors();
        }
    }
    {
        // first pass over MBs to mark overlap and invalid targets skipping first MB
        auto node_iter = cfg.begin() + 1;
        for (auto block_iter =
            m_sec_disassembly->getMaximalBlocks().begin() + 1;
             block_iter < m_sec_disassembly->getMaximalBlocks().end();
             ++block_iter, ++node_iter) {

            (*node_iter).setMaximalBlock(&(*block_iter));
            if ((*block_iter).getBranch().isDirect()
                && !isValidCodeAddr((*block_iter).getBranch().target())) {
                // a branch to an address outside of executable code
                (*node_iter).setToDataAndInvalidatePredecessors();
                continue;
            }
            auto rev_cfg_node_iter = (node_iter) - 1;
            if ((*rev_cfg_node_iter).isPossibleCall()
                && (*rev_cfg_node_iter).getMaximalBlock()->
                    isAppendableBy(*(*node_iter).getMaximalBlock())) {
                (*node_iter).setAsReturnNodeFrom(&(*rev_cfg_node_iter));
            }
            // check for overlap MB
            for (; rev_cfg_node_iter >= m_sec_cfg.m_cfg.begin();
                   --rev_cfg_node_iter) {
                if ((*rev_cfg_node_iter).getMaximalBlock()->endAddr() <=
                    (*node_iter).getMaximalBlock()->addrOfFirstInst()) {
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
    // second pass for setting successors and predecessors to each CFGNode
    for (auto node_iter = cfg.begin();
         node_iter < cfg.end(); ++node_iter) {
        if ((*node_iter).isData()) {
            continue;
        }
        auto current_block = (*node_iter).getMaximalBlock();
        if (current_block->getBranch().isDirect()) {
            auto branch_target = current_block->getBranch().target();
            if (!m_sec_disassembly->
                isWithinSectionAddressSpace(branch_target)) {
                // a valid direct branch can happen to an executable section
                // other than this section.
                continue;
            }
            auto succ = findRemoteSuccessor(branch_target);
            if (succ != nullptr && !succ->isData()) {
                (*node_iter).setRemoteSuccessor(succ);
                succ->addDirectPredecessor(&(*node_iter), branch_target);
//                    std::cout << "MaximalBlock: " << (*node_iter).id()
//                        << " Points to: " << (*succ).id() << "\n";
            } else {
                // a direct branch that doesn't target an MB is data
                (*node_iter).setToDataAndInvalidatePredecessors();
            }
        }
    }
    m_sec_cfg.m_valid = true;
}

bool SectionDisassemblyAnalyzerARM::isValidCodeAddr(addr_t addr) const noexcept {
    // XXX: validity should consider alignment of the address
    return (m_exec_addr_start <= addr) && (addr < m_exec_addr_end);
}

CFGNode *SectionDisassemblyAnalyzerARM::findImmediateSuccessor
    (const CFGNode &cfg_node) noexcept {
    // no direct successor to last cfg node
    if (m_sec_cfg.isLast(&cfg_node)) {
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

CFGNode *SectionDisassemblyAnalyzerARM::findRemoteSuccessor
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

const DisassemblyCFG &SectionDisassemblyAnalyzerARM::getCFG() const noexcept {
    return m_sec_cfg;
}

void SectionDisassemblyAnalyzerARM::refineCFG() {
    if (!m_sec_cfg.isValid()) {
        return;
    }
    for (auto node_iter = m_sec_cfg.m_cfg.begin();
         node_iter < m_sec_cfg.m_cfg.end(); ++node_iter) {
        if ((*node_iter).isData()) {
            continue;
        }
        resolveOverlapBetweenCFGNodes(*node_iter);
        addConditionalBranchToCFG(*node_iter);
        // find maximally valid BB and resolves conflicts between MBs
        resolveValidBasicBlock((*node_iter));

    }
    // PC relative-loads introduce additional conflicts
    for (auto node_iter = m_sec_cfg.m_cfg.begin();
         node_iter < m_sec_cfg.m_cfg.end(); ++node_iter) {
        if ((*node_iter).isData()) {
            continue;
        }
        resolveSwitchStatements(*node_iter);
    }
}

void SectionDisassemblyAnalyzerARM::resolveOverlapBetweenCFGNodes(CFGNode &node) {
    // resolve overlap between MBs by shrinking the next or converting this to data
    if (node.hasOverlapWithOtherNode()
        && !node.getOverlapNode()->isData()) {
        if (node.getOverlapNode()->getMaximalBlock()->
            coversAddressSpaceOf(node.getMaximalBlock())) {
            if (calculateNodeWeight(&node) <
                calculateNodeWeight(node.getOverlapNode())) {
                if (node.getMaximalBlock()->addrOfFirstInst() ==
                    m_sec_cfg.previous(node).getMaximalBlock()->endAddr()) {
                    // XXX: heuristic applied when this node aligns with previous
                    // what if previous is data? what if next is one instruction?
                    node.getOverlapNodePtr()->
                        setCandidateStartAddr(node.getMaximalBlock()->endAddr());
                } else {
                    node.setToDataAndInvalidatePredecessors();
                }
            }
        } else {
            if (node.getOverlapNodePtr()->
                isCandidateStartAddressValid(node.getMaximalBlock()->endAddr())) {
                node.getOverlapNodePtr()->
                    setCandidateStartAddr(node.getMaximalBlock()->endAddr());
            } else if (calculateNodeWeight(&node) <
                calculateNodeWeight(node.getOverlapNode())) {
                node.setToDataAndInvalidatePredecessors();
            } else {
                // overlapping node consists of only one instruction?
                node.getOverlapNodePtr()->setToDataAndInvalidatePredecessors();
            }
        }
    }
}

void SectionDisassemblyAnalyzerARM::resolveValidBasicBlock(CFGNode &node) {
    if (!node.isCandidateStartAddressSet()) {
        // with no objections we take the first instruction
        node.setCandidateStartAddr(node.getMaximalBlock()->addrOfFirstInst());
    }
    if (node.getMaximalBlock()->getBasicBlocksCount() == 1
        || node.getDirectPredecessors().size() == 0) {
        // nothing more to do
        return;
    }
    std::vector<std::pair<CFGNode *, addr_t>> valid_predecessors;
    for (auto &pred_iter: node.getDirectPredecessors()) {
        if (!(pred_iter).first->isData()) {
            valid_predecessors.push_back(pred_iter);
        }
    }
    // The common case where all branches target the same basic block
    for (auto bblock_iter = node.getMaximalBlock()->getBasicBlocks().begin();
         bblock_iter < node.getMaximalBlock()->getBasicBlocks().end();
         ++bblock_iter) {
        unsigned target_count = 0;
        for (auto pred_iter = valid_predecessors.cbegin();
             pred_iter < valid_predecessors.cend(); ++pred_iter) {
            for (addr_t addr : (*bblock_iter).getInstructionAddresses()) {
                if ((*pred_iter).second == addr) {
                    if ((*pred_iter).second < node.getCandidateStartAddr()) {
                        auto overlap_pred =
                            m_sec_cfg.ptrToNodeAt(node.id() - 1);
                        if (calculateNodeWeight((*pred_iter).first) <
                            calculateNodeWeight(overlap_pred)) {
                            (*pred_iter).first->setToDataAndInvalidatePredecessors();
                        } else {
                            overlap_pred->setToDataAndInvalidatePredecessors();
                        }
                    }
                    target_count++;
                    // a predecessor-target tuple is unique
                    break;
                }
            }
        }
        if (target_count == valid_predecessors.size()) {
            if (node.getCandidateStartAddr() < (*bblock_iter).startAddr()) {
                // we advance candidate start address only for
                // valid predecessors
                node.setCandidateStartAddr((*bblock_iter).startAddr());
            }
            return;
        }
    }
    // No basic block satisfies all targets then conflicts should be resolved
    resolveCFGConflicts(node, valid_predecessors);
}

void SectionDisassemblyAnalyzerARM::resolveCFGConflicts
    (CFGNode &node,
     const std::vector<std::pair<CFGNode *, addr_t>> &valid_predecessors) {
    // Conflicts between predecessors needs to be resolved.
//    std::cout << "resolving conflicts for node:" << node.id() << std::endl;
    std::vector<size_t> assigned_predecessors;
    assigned_predecessors.resize(valid_predecessors.size(), 0);
    int valid_bb_idx = 0;
    {
        size_t maximum_weight = 0;
        // find the basic block with maximum weight giving priority to
        // earlier BB.
        for (int i =
            static_cast<int>(node.getMaximalBlock()->getBasicBlocksCount() - 1);
             i >= 0; --i) {
            size_t current_weight = node.getMaximalBlock()->
                getBasicBlockAt(i).instructionCount();
            size_t j = 0;
            for (auto pred_iter = valid_predecessors.cbegin();
                 pred_iter < valid_predecessors.cend();
                 ++pred_iter, ++j) {
                // basic block weight = calculate predecessor instruction count
                //                      + instruction count of BB
                auto addrs = node.getMaximalBlock()->
                    getBasicBlockAt(i).getInstructionAddresses();
                if (std::find(addrs.begin(), addrs.end(), (*pred_iter).second)
                    != addrs.end()) {
                    assigned_predecessors[j] = static_cast<size_t>(i);
                    current_weight += calculateNodeWeight((*pred_iter).first);
                }
            }
            if (current_weight >= maximum_weight) {
                valid_bb_idx = i;
                maximum_weight = current_weight;
            }
        }
    }
    unsigned j = 0;
    for (auto pred_iter = valid_predecessors.cbegin();
         pred_iter < valid_predecessors.cend(); ++pred_iter, ++j) {
        if (assigned_predecessors[j] != valid_bb_idx) {
            // set predecessor to data
            (*pred_iter).first->setToDataAndInvalidatePredecessors();
        }
    }
}

void SectionDisassemblyAnalyzerARM::resolveLoadConflicts(CFGNode &node) {
    // A load conflict can happen between an MB_1 and another MB_2 such that
    // MB_1 < MB_2 (comparing start addresses)
    auto pc_relative_loads =
        m_analyzer.getPCRelativeLoadsInstructions(&node);
    for (auto inst_ptr: pc_relative_loads) {
        // get conflict target node
        // compare weights and shrink the node with less weight
        addr_t target = inst_ptr->addr() + 4 +
            inst_ptr->detail().arm.operands[1].mem.disp;
        target = (target >> 2) << 2; // align target to word address
        CFGNode *target_node =
            findCFGNodeAffectedByLoadStartingFrom(node, target);
        if (target_node == nullptr) {
            shortenToCandidateAddressOrSetToData
                (node, inst_ptr->endAddr());
            continue;
        }
        if (target + 4 <= target_node->getCandidateStartAddr()) {
            continue;
        }
        // XXX: no weight analysis is applied here, that should be handled
        shortenToCandidateAddressOrSetToData((*target_node), target + 4);
        printf("Node %lu shortens node %lu\n", node.id(), target_node->id());
        if (target_node->isData()) {
            auto next_node =
                m_sec_cfg.ptrToNodeAt(target_node->id() + 1);
            if (next_node->getCandidateStartAddr() < target + 4) {
                printf("Inner: node %lu shortens node %lu\n",
                       node.id(),
                       target_node->id());
                shortenToCandidateAddressOrSetToData(*next_node, target + 4);
            }
        }
    }
}

CFGNode *SectionDisassemblyAnalyzerARM::findCFGNodeAffectedByLoadStartingFrom
    (const CFGNode &node, addr_t target) noexcept {

    if (target < node.getMaximalBlock()->endAddr()
        || target > m_exec_addr_end) {
        // A PC-relative load can't target its same MB or load an external address
        return nullptr;
    }
    for (auto node_iter = m_sec_cfg.m_cfg.begin() + node.id() + 1;
         node_iter < m_sec_cfg.m_cfg.end(); ++node_iter) {
        // we only care about affected instructions
        if (target <= (*node_iter).getMaximalBlock()->addrOfLastInst()) {
            return &(*node_iter);
        }
    }
    return nullptr;
}

void SectionDisassemblyAnalyzerARM::shortenToCandidateAddressOrSetToData
    (CFGNode &node, addr_t addr) noexcept {
    if (node.isCandidateStartAddressValid(addr)) {
        node.setCandidateStartAddr(addr);
    } else {
        node.setToDataAndInvalidatePredecessors();
    }
}

void SectionDisassemblyAnalyzerARM::buildCallGraph() {
    // for each node
    // if assigned to procedure
    //     continue
    // buildProcedureStartingFrom (node)
}

void SectionDisassemblyAnalyzerARM::buildProcedureStartingFrom(
    CFGNode &entry_node) {

}

void SectionDisassemblyAnalyzerARM::resolveSwitchStatements
    (CFGNode &node) {
    if (isNotSwitchStatement(node))
        return;
    if (node.getMaximalBlock()->getBranchInstruction()->id() == ARM_INS_TBB) {
        recoverTBBSwitchTable(node);
    }
    if (node.getMaximalBlock()->getBranchInstruction()->id() == ARM_INS_TBH) {
        recoverTBHSwitchTable(node);
    }
    if (node.getMaximalBlock()->getBranchInstruction()->id() == ARM_INS_LDR) {
        recoverLDRSwitchTable(node);
    }
}

bool SectionDisassemblyAnalyzerARM::isNotSwitchStatement
    (const CFGNode &node) const noexcept {
    if (node.getMaximalBlock()->getBranch().isDirect()
        || node.getMaximalBlock()->getBranch().isConditional())
        // a switch stmt can't be direct or conditional
        return true;
    if (node.getMaximalBlock()->getBranchInstruction()->id() == ARM_INS_POP
        || node.getMaximalBlock()->getBranchInstruction()->id() == ARM_INS_BLX
        || node.getMaximalBlock()->getBranchInstruction()->id() == ARM_INS_BL
        || node.getMaximalBlock()->getBranchInstruction()->id() == ARM_INS_BX) {
        return true;
    }
    return false;
}

void SectionDisassemblyAnalyzerARM::addConditionalBranchToCFG(CFGNode &node) {
    if (!node.getMaximalBlock()->getBranch().isConditional()) {
        return;
    }
    if (!isConditionalBranchAffectedByNodeOverlap(node)) {
        // a conditional branch should be valid
        auto succ = findImmediateSuccessor(node);
        if (succ != nullptr && !succ->isData()) {
            node.setImmediateSuccessor(succ);
            succ->addDirectPredecessor
                (&node, node.getMaximalBlock()->endAddr());
        } else {
            // a conditional branch without a direct successor is data
            node.setToDataAndInvalidatePredecessors();
        }
    }
}

bool SectionDisassemblyAnalyzerARM::isConditionalBranchAffectedByNodeOverlap
    (const CFGNode &node) const noexcept {
    if (!node.isCandidateStartAddressSet()
        || node.getMaximalBlock()->getBranchInstruction()->id() == ARM_INS_CBZ
        || node.getMaximalBlock()->getBranchInstruction()->id()
            == ARM_INS_CBNZ) {
        // if there was no overlap or branches are not affected by context.
        // additionally larger nodes are not affected (heuristic)
        return false;
    } else {
        for (auto inst_iter =
            node.getMaximalBlock()->getAllInstructions().cbegin();
             inst_iter < node.getMaximalBlock()->getAllInstructions().cend();
             inst_iter++) {
            if ((*inst_iter).id() == ARM_INS_CMP
                || (*inst_iter).id() == ARM_INS_CMN
                || (*inst_iter).id() == ARM_INS_IT) {
                // if there was a conditional execution instruction eliminated
                //  by overlap analysis then we won't consider the block.
                // TODO: check if a conditional execution instruction actually
                // affects the branch instruction
                return true;
            }
            if ((*inst_iter).addr() > node.getCandidateStartAddr()) {
                return false;
            }
        }
    }
}

void SectionDisassemblyAnalyzerARM::recoverTBBSwitchTable(CFGNode &node) {
    const uint8_t *code_ptr = (m_sec_disassembly->ptrToData() + 4 +
        +(node.getMaximalBlock()->getBranchInstruction()->addr()
            - m_sec_disassembly->startAddr()));
    const addr_t base_addr =
        node.getMaximalBlock()->getBranchInstruction()->addr() + 4;
    addr_t minimum_switch_case_addr = m_exec_addr_end;
    CFGNode *earliest_switch_table_node = nullptr;
    addr_t current_addr = base_addr;
    addr_t last_target = 0;
    while (current_addr < minimum_switch_case_addr) {
        addr_t target = base_addr + (*code_ptr) * 2;
        if (last_target != target) {
            auto target_node = findSwitchTargetStartingFromNode(node, target);
            if (target_node == nullptr) {
                // switch table looks invalid!
                return;
            }
            if (!target_node->isSwitchCaseStatement()) {
                // there are many redundancies in a switch table
                target_node->setAsSwitchCaseFor(&node);
            }
            if (target < minimum_switch_case_addr
                && target > node.getCandidateStartAddr()) {
                minimum_switch_case_addr = target;
                earliest_switch_table_node = target_node;
            }
        }
        code_ptr++;
        current_addr++;
        last_target = target;
    }
    // clean-up
    if (earliest_switch_table_node != nullptr) {
        earliest_switch_table_node->
            setCandidateStartAddr(minimum_switch_case_addr);
        for (auto node_iter = m_sec_cfg.m_cfg.begin() + node.id() + 1;
             node_iter
                 < m_sec_cfg.m_cfg.begin() + earliest_switch_table_node->id();
             ++node_iter) {
            (*node_iter).setType(CFGNodeKind::kData);
        }
    }
}

void SectionDisassemblyAnalyzerARM::recoverTBHSwitchTable(CFGNode &node) {
    // pointer to the first byte after TBH
    const uint8_t *code_ptr = (m_sec_disassembly->ptrToData() + 4 +
        +(node.getMaximalBlock()->getBranchInstruction()->addr()
            - m_sec_disassembly->startAddr()));
    const addr_t base_addr =
        node.getMaximalBlock()->getBranchInstruction()->addr() + 4;
    addr_t minimum_switch_case_addr = m_exec_addr_end;
    CFGNode *earliest_switch_table_node = nullptr;
    addr_t current_addr = base_addr;
    addr_t last_target = 0;
    bool is_jump_table_bounded = true;
    while (current_addr < minimum_switch_case_addr) {
        addr_t target = base_addr +
            (*(reinterpret_cast<const uint16_t *>(code_ptr))) * 2;
        if (last_target != target) {
            auto target_node = findSwitchTargetStartingFromNode(node, target);
            if (target_node == nullptr) {
                // switch table looks invalid or unbounded!
                is_jump_table_bounded = false;
                break;
            }
            if (!target_node->isSwitchCaseStatement()) {
                // is settable to switch case
                // if target = candidate -> true, target < candidate_start->false
                // target > candidate start validate predecessors.
                // there are many redundancies in a switch table
                target_node->setAsSwitchCaseFor(&node);
            }
            if (target < minimum_switch_case_addr
                && target > node.getCandidateStartAddr()) {
                minimum_switch_case_addr = target;
                earliest_switch_table_node = target_node;
            }
        }
        code_ptr += 2;
        current_addr += 2;
        last_target = target;
    }
    if (!is_jump_table_bounded) {
        earliest_switch_table_node =
            findCFGNodeAffectedByLoadStartingFrom(node, current_addr);
        if (earliest_switch_table_node == nullptr
            || earliest_switch_table_node->id() == node.id()) {
            return;
        }
        minimum_switch_case_addr =
            earliest_switch_table_node->getMinTargetAddrOfValidPredecessor();
    }
    // clean-up
    earliest_switch_table_node->
        setCandidateStartAddr(minimum_switch_case_addr);
    for (auto node_iter = m_sec_cfg.m_cfg.begin() + node.id() + 1;
         node_iter
             < m_sec_cfg.m_cfg.begin() + earliest_switch_table_node->id();
         ++node_iter) {
        (*node_iter).setType(CFGNodeKind::kData);
    }

}

void SectionDisassemblyAnalyzerARM::recoverLDRSwitchTable(CFGNode &node) {
    const uint8_t *code_ptr = (m_sec_disassembly->ptrToData() + 4 +
        +(node.getMaximalBlock()->getBranchInstruction()->addr()
            - m_sec_disassembly->startAddr()));
    addr_t current_addr =
        node.getMaximalBlock()->getBranchInstruction()->addr() + 4;
    if (current_addr % 4 != 0) {
        code_ptr += 2;
        current_addr += 2;
    }
    addr_t minimum_switch_case_addr = m_exec_addr_end;
    CFGNode *earliest_switch_table_node = nullptr;
    addr_t last_target = 0;
    while (current_addr < minimum_switch_case_addr) {
        uint32_t target = *(reinterpret_cast<const uint32_t *>(code_ptr))
            & 0xFFFFFFFE;
        if (last_target != target) {
            auto target_node = findSwitchTargetStartingFromNode(node, target);
            if (target_node == nullptr) {
                // switch table looks invalid!
                return;
            }
            if (!target_node->isSwitchCaseStatement()) {
                // there are many redundancies in a switch table
                target_node->setAsSwitchCaseFor(&node);
            }
            if (target < minimum_switch_case_addr
                && target > node.getCandidateStartAddr()) {
                minimum_switch_case_addr = target;
                earliest_switch_table_node = target_node;
            }
        }
        code_ptr += 4;
        current_addr += 4;
        last_target = target;
    }
    // clean-up
    if (earliest_switch_table_node != nullptr) {
        earliest_switch_table_node->
            setCandidateStartAddr(minimum_switch_case_addr);
        for (auto node_iter = m_sec_cfg.m_cfg.begin() + node.id() + 1;
             node_iter
                 < m_sec_cfg.m_cfg.begin() + earliest_switch_table_node->id();
             ++node_iter) {
            (*node_iter).setType(CFGNodeKind::kData);
        }
    }
}

CFGNode *SectionDisassemblyAnalyzerARM::findSwitchTargetStartingFromNode
    (CFGNode &node, addr_t target_addr) {
    printf("Node: %lu at %lx Target: %lx\n", node.id(),
           node.getCandidateStartAddr(), target_addr);
    if (target_addr < m_exec_addr_start || target_addr > m_exec_addr_end) {
        return nullptr;
    }
    // switch tables can branch to an node that precedes current node
    size_t first = 0;
    size_t middle = node.id() + 20;
    size_t last = m_sec_disassembly->maximalBlockCount() - 1;
    while (middle > first) {
        if (target_addr <
            m_sec_disassembly->maximalBlockAt(middle).addrOfLastInst()) {
            last = middle;
        } else {
            first = middle;
        }
        middle = (first + last) / 2;
    }
    // assuming that switch table targets are valid instructions
    if (m_sec_cfg.ptrToNodeAt(last)->isData()) {
        return m_sec_cfg.ptrToNodeAt(last)->m_overlap_node;
    } else if (m_sec_disassembly->
        maximalBlockAt(last).isWithinAddressSpace(target_addr)) {
        return m_sec_cfg.ptrToNodeAt(last);
    }
    if (m_sec_disassembly->
        maximalBlockAt(first).isWithinAddressSpace(target_addr)) {
        return m_sec_cfg.ptrToNodeAt(first);
    }
    return nullptr;
}
}
