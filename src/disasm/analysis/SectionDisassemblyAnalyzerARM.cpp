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
#include <cassert>
#include <disasm/MCParser.h>
#include <disasm/RawInstWrapper.h>
#include <deque>

namespace disasm {

SectionDisassemblyAnalyzerARM::SectionDisassemblyAnalyzerARM
    (elf::elf *elf_file, SectionDisassemblyARM *sec_disasm) :
    m_elf_file{elf_file},
    m_sec_disasm{sec_disasm},
    m_analyzer{sec_disasm->getISA()},
    m_call_graph{sec_disasm->secStartAddr(), sec_disasm->secEndAddr()},
    m_plt_map{elf_file} {
    addr_t start_addr = UINT64_MAX;
    addr_t end_addr = 0;
    for (auto &sec : m_elf_file->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            if (sec.get_hdr().addr < start_addr) {
                start_addr = sec.get_hdr().addr;
            }
            if (end_addr < sec.get_hdr().addr + sec.get_hdr().size) {
                end_addr = sec.get_hdr().addr + sec.get_hdr().size;
            }
        }
    }
    m_exec_addr_start = start_addr;
    m_exec_addr_end = end_addr;
}

size_t SectionDisassemblyAnalyzerARM::calculateBasicBlockWeight
    (const CFGNode &node, const BasicBlock &basic_block) const noexcept {
    unsigned pred_weight = 0;
    for (auto pred_iter = node.getDirectPredecessors().cbegin();
         pred_iter < node.getDirectPredecessors().cend(); ++pred_iter) {
        if (!(*pred_iter).node()->isData()) {
            pred_weight +=
                (*pred_iter).node()->maximalBlock()->instructionsCount();
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
            (*pred_iter).node()->maximalBlock()->instructionsCount();
    }
    return node->maximalBlock()->instructionsCount() + pred_weight;
}

void SectionDisassemblyAnalyzerARM::buildCFG() {
    if (m_sec_disasm->maximalBlockCount() == 0) {
        return;
    }
    // work directly with the vector of CFGNode
    auto &cfg = m_sec_cfg.m_cfg;
    cfg.resize(m_sec_disasm->maximalBlockCount());
    {
        MaximalBlock *first_maximal_block =
            &(*m_sec_disasm->getMaximalBlocks().begin());
        // handle first MB
        cfg.front().setMaximalBlock(first_maximal_block);
        if (first_maximal_block->branchInfo().isDirect()
            && !isValidCodeAddr(first_maximal_block->branchInfo().target())) {
            // a branch to an address outside of executable code
            cfg.front().setToDataAndInvalidatePredecessors();
        }
    }
    {
        // first pass over MBs to mark overlap and invalid targets skipping first MB
        auto node_iter = cfg.begin() + 1;
        for (auto block_iter =
            m_sec_disasm->getMaximalBlocks().begin() + 1;
             block_iter < m_sec_disasm->getMaximalBlocks().end();
             ++block_iter, ++node_iter) {

            (*node_iter).setMaximalBlock(&(*block_iter));
            if ((*block_iter).branchInfo().isDirect()
                && !isValidCodeAddr((*block_iter).branchInfo().target())) {
                // a branch to an address outside of executable code
                (*node_iter).setToDataAndInvalidatePredecessors();
                continue;
            }
            auto rev_cfg_node_iter = (node_iter) - 1;
            // check for overlap MB
            for (; rev_cfg_node_iter >= m_sec_cfg.m_cfg.begin();
                   --rev_cfg_node_iter) {
                if ((*rev_cfg_node_iter).maximalBlock()->endAddr() <=
                    (*node_iter).maximalBlock()->addrOfFirstInst()) {
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
        auto current_block = (*node_iter).maximalBlock();
        if (current_block->branchInfo().isDirect()) {
            auto branch_target = current_block->branchInfo().target();
            if (!m_sec_disasm->
                isWithinSectionAddressSpace(branch_target)) {
                // a valid direct branch can happen to an executable section
                // other than this section.
                continue;
            }
            auto succ = findRemoteSuccessor(branch_target);
            if (succ != nullptr && !succ->isData()) {
                (*node_iter).setRemoteSuccessor(succ);
                succ->addRemotePredecessor(&(*node_iter), branch_target);
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
    if (!direct_succ->isData()) {
        if (direct_succ->maximalBlock()->
            isAddressOfInstruction(cfg_node.maximalBlock()->endAddr())) {
            return direct_succ;
        }
    } else {
        auto second_direct_succ =
            &(*(m_sec_cfg.m_cfg.begin() + cfg_node.id() + 2));
        if (second_direct_succ != nullptr
            && second_direct_succ->maximalBlock()->
                isAddressOfInstruction(cfg_node.maximalBlock()->endAddr())) {
            return second_direct_succ;
        }
    }
    auto overlap_node = direct_succ->getOverlapNodePtr();
    if (overlap_node != nullptr) {
        if (!overlap_node->isData() && overlap_node->maximalBlock()->
            isAddressOfInstruction(cfg_node.maximalBlock()->endAddr())) {
            return overlap_node;
        }
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
    size_t last = m_sec_disasm->maximalBlockCount() - 1;
    size_t middle = (first + last) / 2;
    while (middle > first) {
        if (target <
            m_sec_disasm->maximalBlockAt(middle).addrOfLastInst()) {
            last = middle;
        } else {
            first = middle;
        }
        middle = (first + last) / 2;
    }
    if (m_sec_disasm->maximalBlockAt(last).isAddressOfInstruction(target)) {
        return m_sec_cfg.ptrToNodeAt(last);
    }
    if (m_sec_disasm->maximalBlockAt(first).isAddressOfInstruction(target)) {
        return m_sec_cfg.ptrToNodeAt(first);
    }
    // Handle overlap MBs.
    auto overlap_node = m_sec_cfg.getNodeAt(last).getOverlapNode();
    if (overlap_node != nullptr &&
        overlap_node->maximalBlock()->isAddressOfInstruction(target)) {
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
    MCParser parser;
    parser.initialize(CS_ARCH_ARM, CS_MODE_THUMB, m_sec_disasm->secEndAddr());
    for (auto node_iter = m_sec_cfg.m_cfg.begin();
         node_iter < m_sec_cfg.m_cfg.end(); ++node_iter) {
        if ((*node_iter).isData())
            continue;
        resolveSpaceOverlap(*node_iter);
        if ((*node_iter).isData())
            continue;
        addCallReturnRelation(*node_iter);
        auto &node = (*node_iter);
        if (!node.isCandidateStartAddressSet()) {
            node.setCandidateStartAddr(node.maximalBlock()->addrOfFirstInst());
        }
        // Fix insts errors caused by invalid IT
        addr_t current = node.getCandidateStartAddr();
        for (auto inst_iter =
            node.maximalBlockPtr()->getInstructionsRef().begin();
             inst_iter < node.maximalBlockPtr()->getInstructionsRef().end();
             ++inst_iter) {
            if ((*inst_iter).addr() == current) {
                current += (*inst_iter).size();
            } else {
                if ((*inst_iter).id() == ARM_INS_IT
                    && (*inst_iter).detail().arm.cc != ARM_CC_AL) {
                    RawInstWrapper inst;
                    auto addr = (*inst_iter).addr() + 2;
                    auto code_ptr = m_sec_disasm->physicalAddrOf(addr);
                    auto it_block_size = (*inst_iter).mnemonic().length() - 1;
                    inst_iter++;
                    for (;
                        inst_iter
                            < node.maximalBlockPtr()->getInstructionsRef().end()
                            && it_block_size > 0;
                        ++inst_iter) {
                        if ((*inst_iter).addr() != addr) continue;
                        parser.disasm(code_ptr, 4, addr, inst.rawPtr());
                        (*inst_iter).setMnemonic(inst.rawPtr()->mnemonic);
                        (*inst_iter).setDetail(*inst.rawPtr()->detail);
                        addr += inst.rawPtr()->size;
                        code_ptr += inst.rawPtr()->size;
                        --it_block_size;
                    }
                    bool is_conditional =
                        node.maximalBlock()->branchInstruction()->condition()
                            != ARM_CC_AL;
                    node.maximalBlockPtr()->setBranchCondition(is_conditional);
//                    if (it_block_size == 0) {
//                        current = addr;
//                        continue;
//                    }
                    // IT errors can span more than one MB!
//                    auto &next_node = *(node_iter + 1);
//                    for (auto inst_iter2 =
//                        next_node.maximalBlockPtr()->getInstructionsRef().begin();
//                         it_block_size > 0
//                             && inst_iter2 <
//                                 next_node.maximalBlockPtr()->getInstructionsRef().end();
//                         ++inst_iter2) {
//                        if ((*inst_iter2).addr() == addr) {
//                            parser.disasm(code_ptr, 4, addr, inst.rawPtr());
//                            (*inst_iter2).setMnemonic(inst.rawPtr()->mnemonic);
//                            (*inst_iter2).setDetail(*inst.rawPtr()->detail);
//                            addr += inst.rawPtr()->size;
//                            code_ptr += inst.rawPtr()->size;
//                            --it_block_size;
//                        }
//                    }
//                    is_conditional =
//                        next_node.maximalBlock()->branchInstruction()->condition()
//                            != ARM_CC_AL;
//                    next_node.maximalBlockPtr()->
//                        setBranchCondition(is_conditional);
//                    assert(it_block_size == 0 && "Invalid IT spans more than "
//                        "two MBs!");
                }
            }
        }
        addConditionalBranchToCFG(*node_iter);
        // find maximally valid BB and resolves conflicts between MBs
//        resolveValidBasicBlock((*node_iter));
    }
    recoverSwitchStatements();
    identifyPCRelativeLoadData();
}

void SectionDisassemblyAnalyzerARM::resolveSpaceOverlap(CFGNode &node) {
    if (!node.hasOverlapWithOtherNode() || node.getOverlapNode()->isData()) {
        return;
    }
    // resolve overlap between MBs by shrinking the next or converting this to data
    if (node.getOverlapNode()->maximalBlock()->
        coversAddressSpaceOf(node.maximalBlock())) {
        if (calculateNodeWeight(&node) <
            calculateNodeWeight(node.getOverlapNode())) {
            if (m_sec_cfg.previous(node).isAppendableBy(&node)
                && calculateNodeWeight(&m_sec_cfg.previous(node)) > 2) {
                // TODO: alignment should be revisted!!
                // XXX: heuristic applied when this node aligns with previous
                // what if next is one instruction?
                node.getOverlapNodePtr()->
                    setCandidateStartAddr(node.maximalBlock()->endAddr());
            } else {
                node.setToDataAndInvalidatePredecessors();
            }
        }
    } else {
        if (node.getOverlapNodePtr()->
            isCandidateStartAddressValid(node.maximalBlock()->endAddr())) {
            auto nested_overlap =
                node.getOverlapNodePtr()->getOverlapNodePtr();
            if (nested_overlap != nullptr
                && node.isAppendableBy(nested_overlap)) {
                node.getOverlapNodePtr()->setToDataAndInvalidatePredecessors();
            } else {
                node.getOverlapNodePtr()->
                    setCandidateStartAddr(node.maximalBlock()->endAddr());
            }
        } else if (calculateNodeWeight(&node) <
            calculateNodeWeight(node.getOverlapNode())) {
            node.setToDataAndInvalidatePredecessors();
        } else {
            // overlapping node consists of only one instruction?
            node.getOverlapNodePtr()->setToDataAndInvalidatePredecessors();
        }
    }
}

void SectionDisassemblyAnalyzerARM::resolveValidBasicBlock(CFGNode &node) {

    if (node.maximalBlock()->getBasicBlocksCount() == 1
        || node.getDirectPredecessors().size() == 0) {
        // nothing more to do
        return;
    }
    std::vector<CFGEdge> valid_predecessors;
    for (auto &pred_iter: node.getDirectPredecessors()) {
        if (!(pred_iter).node()->isData()) {
            valid_predecessors.push_back(pred_iter);
        }
    }
    // The common case where all branches target the same basic block
    for (auto bblock_iter = node.maximalBlock()->getBasicBlocks().begin();
         bblock_iter < node.maximalBlock()->getBasicBlocks().end();
         ++bblock_iter) {
        unsigned target_count = 0;
        for (auto pred_iter = valid_predecessors.cbegin();
             pred_iter < valid_predecessors.cend(); ++pred_iter) {
            for (addr_t addr : (*bblock_iter).getInstructionAddresses()) {
                if ((*pred_iter).targetAddr() == addr) {
                    if ((*pred_iter).targetAddr()
                        < node.getCandidateStartAddr()) {
                        auto overlap_pred =
                            m_sec_cfg.ptrToNodeAt(node.id() - 1);
                        if (calculateNodeWeight((*pred_iter).node()) <
                            calculateNodeWeight(overlap_pred)) {
                            (*pred_iter).node()->setToDataAndInvalidatePredecessors();
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
                // TODO: better handling of conflicts here
            }
            return;
        }
    }
    // No basic block satisfies all targets then conflicts should be resolved
    resolveCFGConflicts(node, valid_predecessors);
}

void SectionDisassemblyAnalyzerARM::resolveCFGConflicts
    (CFGNode &node, const std::vector<CFGEdge> &valid_predecessors) {
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
            static_cast<int>(node.maximalBlock()->getBasicBlocksCount() - 1);
             i >= 0; --i) {
            size_t current_weight = node.maximalBlock()->
                getBasicBlockAt(i).instructionCount();
            size_t j = 0;
            for (auto pred_iter = valid_predecessors.cbegin();
                 pred_iter < valid_predecessors.cend();
                 ++pred_iter, ++j) {
                // basic block weight = calculate predecessor instruction count
                //                      + instruction count of BB
                auto addrs = node.maximalBlock()->
                    getBasicBlockAt(i).getInstructionAddresses();
                if (std::find(addrs.begin(),
                              addrs.end(),
                              (*pred_iter).targetAddr())
                    != addrs.end()) {
                    assigned_predecessors[j] = static_cast<size_t>(i);
                    current_weight += calculateNodeWeight((*pred_iter).node());
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
            (*pred_iter).node()->setToDataAndInvalidatePredecessors();
        }
    }
}

void SectionDisassemblyAnalyzerARM::identifyPCRelativeLoadData() {
    std::deque<addr_t> data_word_addrs;
    for (auto &node : m_sec_cfg.m_cfg) {
        if (node.getType() == CFGNodeType::kData) {
            continue;
        }
        // set PC-relative words to data
        for (const auto wordAddr : data_word_addrs) {
            if (wordAddr + 4 < node.maximalBlock()->addrOfFirstInst()) {
                data_word_addrs.pop_front();
                continue;
            }
            if (wordAddr < node.maximalBlock()->endAddr()) {
                if (wordAddr < node.maximalBlock()->addrOfLastInst()) {
                    node.setCandidateStartAddr(wordAddr + 4);
                } else {
                    node.setToDataAndInvalidatePredecessors();
                }
            }
        }
        // Get PC-relative load instructions
        auto pc_relative_load_insts =
            m_analyzer.getPCRelativeLoadInstructions(&node);
        if (pc_relative_load_insts.size() == 0) {
            continue;
        }
        // TODO: better analysis to identify invalid PC-relative loads
        addr_t minimum_pred =
            (node.getDirectPredecessors().size() == 0) ? 0 : UINT64_MAX;
        for (const auto &pred : node.getDirectPredecessors()) {
            if (pred.targetAddr() < minimum_pred) {
                minimum_pred = pred.targetAddr();
            }
        }
        if (pc_relative_load_insts[0]->addr() < minimum_pred) {
            continue;
        }
        for (auto inst_ptr: pc_relative_load_insts) {
            addr_t target_addr = ((inst_ptr->addr() >> 2) << 2)
                + 4 + inst_ptr->detail().arm.operands[1].mem.disp;
            if (std::find(data_word_addrs.begin(),
                          data_word_addrs.end(),
                          target_addr) == data_word_addrs.end()) {
                data_word_addrs.push_back(target_addr);
                if (inst_ptr->id() == ARM_INS_VLDR
                    && ARM_REG_D0 <= inst_ptr->detail().arm.operands[0].reg
                    && inst_ptr->detail().arm.operands[0].reg <= ARM_REG_D31) {
                    // D register hold double words.
                    data_word_addrs.push_back(target_addr + 4);
                }
            }
        }
        if (pc_relative_load_insts.size() > 0) {
            std::sort(data_word_addrs.begin(), data_word_addrs.end());
        }
    }
}

void SectionDisassemblyAnalyzerARM::recoverSwitchStatements() {
    std::vector<SectionDisassemblyAnalyzerARM::SwitchTableData> sw_data_vec;
    for (auto node_iter = m_sec_cfg.m_cfg.begin();
         node_iter < m_sec_cfg.m_cfg.end(); ++node_iter) {
        if ((*node_iter).isData() || isNotSwitchStatement(*node_iter))
            continue;
        if ((*node_iter).maximalBlock()->
            branchInstruction()->id() == ARM_INS_TBB) {
            sw_data_vec.emplace_back(recoverTBBSwitchTable((*node_iter)));
        } else if ((*node_iter).maximalBlock()->
            branchInstruction()->id() == ARM_INS_TBH) {
            sw_data_vec.emplace_back(recoverTBHSwitchTable((*node_iter)));
        } else if ((*node_iter).maximalBlock()->
            branchInstruction()->id() == ARM_INS_LDR
            && (*node_iter).maximalBlock()->
                branchInstruction()->detail().arm.op_count == 2) {
            sw_data_vec.emplace_back(recoverLDRSwitchTable(*node_iter));
        }
    }
    for (auto &table_data : sw_data_vec) {
        switchTableCleanUp(table_data);
    }
}

bool SectionDisassemblyAnalyzerARM::isNotSwitchStatement
    (const CFGNode &node) const noexcept {
    if (node.maximalBlock()->branchInfo().isDirect()
        || node.maximalBlock()->branchInfo().isConditional())
        // a switch stmt can't be direct or conditional
        return true;
    if (node.maximalBlock()->branchInstruction()->id() == ARM_INS_POP
        || node.maximalBlock()->branchInstruction()->id() == ARM_INS_BLX
        || node.maximalBlock()->branchInstruction()->id() == ARM_INS_BL
        || node.maximalBlock()->branchInstruction()->id() == ARM_INS_BX) {
        return true;
    }
    return false;
}

void SectionDisassemblyAnalyzerARM::addConditionalBranchToCFG(CFGNode &node) {
    if (!node.maximalBlock()->branchInfo().isConditional()) {
        return;
    }
    // a conditional branch should be valid
    auto succ = findImmediateSuccessor(node);
    if (succ != nullptr) {
        node.setImmediateSuccessor(succ);
        succ->addImmediatePredecessor
            (&node, node.maximalBlock()->endAddr());
    } else {
        // a conditional branch without a direct successor is data
        node.setToDataAndInvalidatePredecessors();
    }
}

bool SectionDisassemblyAnalyzerARM::isConditionalBranchAffectedByNodeOverlap
    (const CFGNode &node) const noexcept {
    if (node.maximalBlock()->branchInstruction()->id() == ARM_INS_CBZ
        || node.maximalBlock()->branchInstruction()->id() == ARM_INS_CBNZ) {
        // these instructions are not affected
        return false;
    }
    if (!node.isCandidateStartAddressSet()) {
        // if there was no overlap or branches are not affected by context.
        // additionally larger nodes are not affected (heuristic)
        return false;
    } else {
        for (auto inst_iter =
            node.maximalBlock()->getInstructions().rbegin() + 1;
             inst_iter < node.maximalBlock()->getInstructions().rend();
             ++inst_iter) {
            if ((*inst_iter).id() == ARM_INS_CMP
                || (*inst_iter).id() == ARM_INS_CMN
                || (*inst_iter).id() == ARM_INS_IT) {
                if ((*inst_iter).addr() < node.getCandidateStartAddr())
                    return true;
                else
                    return false;
            }
            if ((*inst_iter).detail().arm.cc == ARM_CC_AL) {
                return false;
            }
        }
    }
    return true;
}

SectionDisassemblyAnalyzerARM::SwitchTableData
SectionDisassemblyAnalyzerARM::recoverTBBSwitchTable(CFGNode &node) {
    // assuming TBB is always based on PC
    const addr_t base_addr =
        node.maximalBlock()->branchInstruction()->addr() + 4;
    const uint8_t *code_ptr = m_sec_disasm->physicalAddrOf(base_addr);
    addr_t minimum_switch_case_addr = m_exec_addr_end;
    addr_t current_addr = base_addr;
    std::unordered_map<addr_t, bool> target_map;
    while (current_addr < minimum_switch_case_addr) {
        addr_t target = base_addr + (*code_ptr) * 2;
        auto insert_result = target_map.insert({target, false});
        // there are many redundancies in a switch table
        if (insert_result.second) {
            if (target < current_addr) {
                return SwitchData(&node, 1, current_addr);
            }
            auto target_node = findSwitchTableTarget(target);
            if (target_node == nullptr) {
                // switch table looks padded or not bounded!
                return SwitchData(&node, 1, current_addr);
            }
            target_node->setAsSwitchCaseFor(&node, target);
            if (target < minimum_switch_case_addr) {
                minimum_switch_case_addr = target;
            }
        }
        code_ptr++;
        current_addr++;
    }
    return SwitchData(&node, 1, 0);
}

SectionDisassemblyAnalyzerARM::SwitchTableData
SectionDisassemblyAnalyzerARM::recoverTBHSwitchTable(CFGNode &node) {
    // assuming TBH is always based on PC
    const addr_t base_addr =
        node.maximalBlock()->branchInstruction()->addr() + 4;
    const uint8_t *code_ptr = m_sec_disasm->physicalAddrOf(base_addr);
    addr_t minimum_switch_case_addr = m_exec_addr_end;
    addr_t current_addr = base_addr;
    std::unordered_map<addr_t, bool> target_map;
    while (current_addr < minimum_switch_case_addr) {
        addr_t target = base_addr +
            (*(reinterpret_cast<const uint16_t *>(code_ptr))) * 2;
        auto insert_result = target_map.insert({target, false});
        if (insert_result.second) {
            if (target < current_addr) {
                return SwitchData(&node, 1, current_addr);
            }
            // there are many redundancies in a switch table
            auto target_node = findSwitchTableTarget(target);
            if (target_node == nullptr) {
                // switch table looks padded or not bounded!
                return SwitchData(&node, 2, current_addr);
            }
            target_node->setAsSwitchCaseFor(&node, target);
            if (target < minimum_switch_case_addr) {
                minimum_switch_case_addr = target;
            }
        }
        code_ptr += 2;
        current_addr += 2;
    }
    return SwitchData(&node, 2, 0);
}

SectionDisassemblyAnalyzerARM::SwitchTableData
SectionDisassemblyAnalyzerARM::recoverLDRSwitchTable(CFGNode &node) {
    const addr_t base_addr = m_analyzer.recoverLDRSwitchBaseAddr(node);
    const uint8_t *code_ptr = m_sec_disasm->physicalAddrOf(base_addr);
    addr_t current_addr = base_addr;
    addr_t minimum_switch_case_addr = m_exec_addr_end;
    std::unordered_map<addr_t, bool> target_map;
    while (current_addr < minimum_switch_case_addr) {
        uint32_t target = *(reinterpret_cast<const uint32_t *>(code_ptr))
            & 0xFFFFFFFE;
        auto insert_result = target_map.insert({target, false});
        // there are many redundancies in a switch table
        if (insert_result.second) {
            auto target_node = findSwitchTableTarget(target);
            if (target_node == nullptr) {
                // switch table looks padded or not bounded!
                return SwitchData(&node, 4, current_addr);
            }
            target_node->setAsSwitchCaseFor(&node, target);
            if (target < minimum_switch_case_addr
                && target > base_addr) {
                // we pick only nodes after the current node since jumping
                // to default case can happen earlier
                minimum_switch_case_addr = target;
            }
        }
        code_ptr += 4;
        current_addr += 4;
    }
    return SwitchData(&node, 4, 0);
}

int
SectionDisassemblyAnalyzerARM::recoverLimitOfSwitchTable
    (const CFGNode &node) const noexcept {

    if (m_sec_cfg.previous(node).maximalBlock()->branchInfo().isConditional()) {
        // TODO: check for "cmp" with index register and return compared value
    }
    return 0;
}

void SectionDisassemblyAnalyzerARM::switchTableCleanUp
    (SwitchTableData &table_data) noexcept {
    for (auto node_iter = m_sec_cfg.m_cfg.begin() + table_data.m_node->id() + 1;
         node_iter < m_sec_cfg.m_cfg.end();
         ++node_iter) {
        if ((*node_iter).getType() == CFGNodeType::kData) {
            continue;
        }
        auto min_addr = (*node_iter).getMinTargetAddrOfValidPredecessor();
        if (min_addr == 0) {
            (*node_iter).setType(CFGNodeType::kData);
//            printf("Switch clean up at table_data %lu invalidating table_data %lu\n",
//                   table_data.id(), (*node_iter).id());
        } else {
            (*node_iter).setCandidateStartAddr(min_addr);
            if (min_addr < table_data.m_table_end) {
                // an unbounded switch table with invalid edges, rollack!
                for (int i = 0;
                     i < (table_data.m_table_end - min_addr)
                         / table_data.m_table_type;
                     ++i) {
                    table_data.m_node->m_indirect_succs.back()
                        .node()->m_indirect_preds.pop_back();
                    table_data.m_node->m_indirect_succs.pop_back();
                }
            }
            break;
        }
    }
}

CFGNode *SectionDisassemblyAnalyzerARM::findSwitchTableTarget
    (addr_t target_addr) {
    if (target_addr < m_exec_addr_start || target_addr >= m_exec_addr_end) {
        return nullptr;
    }
    // switch tables can branch to an node that precedes current node
    size_t first = 0;
    size_t last = m_sec_disasm->maximalBlockCount() - 1;
    size_t middle = (first + last) / 2;
    while (middle > first) {
        if (target_addr <
            m_sec_disasm->maximalBlockAt(middle).addrOfLastInst()) {
            last = middle;
        } else {
            first = middle;
        }
        middle = (first + last) / 2;
    }
    // assuming that switch table targets are valid instructions
    if (m_sec_cfg.ptrToNodeAt(last)->isData()) {
        if (m_sec_cfg.ptrToNodeAt(last)->m_overlap_node != nullptr) {
            return m_sec_cfg.ptrToNodeAt(last)->m_overlap_node;
        }
    } else if (m_sec_disasm->
        maximalBlockAt(last).isWithinAddressSpace(target_addr)) {
        return m_sec_cfg.ptrToNodeAt(last);
    }
    if (m_sec_disasm->
        maximalBlockAt(first).isWithinAddressSpace(target_addr)) {
        return m_sec_cfg.ptrToNodeAt(first);
    }
    return nullptr;
}

addr_t SectionDisassemblyAnalyzerARM::validateProcedure(const ICFGNode &proc) noexcept {

    for (auto node_iter =
        std::next(m_sec_cfg.m_cfg.begin(), proc.entryNode()->id() + 1);
         node_iter < m_sec_cfg.m_cfg.end()
             && (*node_iter).id() <= proc.m_end_node->id();
         ++node_iter) {
        if ((*node_iter).isData()) continue;
        // an internal node with no predecessors can either be data
        // or an actual entry.
        if ((*node_iter).procedure_id() != proc.id()) {
            printf("Unreachable MB %lu at %lx in proc %lx covered by %lx\n",
                   (*node_iter).id(),
                   (*node_iter).getCandidateStartAddr(),
                   (*node_iter).procedure_id(),
                   proc.m_entry_addr);
//            auto proc_node = m_call_graph.AddProcedure
//                ((*node_iter).getCandidateStartAddr(), &(*node_iter), ICFGProcedureType::kInner);
//            proc_node->m_estimated_end_addr = proc.m_estimated_end_addr;
//            buildProcedure(*proc_node);
        }
    }
}

void SectionDisassemblyAnalyzerARM::buildCallGraph() {
    // a procedure holds an average of 20 basic blocks!
    m_call_graph.reserve(m_sec_cfg.m_cfg.size() / 20);
    // recover a map of target addresses and direct call sites
    recoverDirectCalledProcedures();
    // Initial call graph where every directly reachable procedure is identified
    //  together with its overestimated address space
    auto &untraversed_procedures = m_call_graph.buildInitialCallGraph();
    // building directly called procedures.
    for (auto &proc : untraversed_procedures) {
        buildProcedure(proc);
        m_call_graph.checkNonReturnProcedureAndFixCallers(proc);
    }
    // a pass to identify all remaining procedures.
    // these are either tail-called, indirectly called, or not called at all.
    auto proc_iter = m_call_graph.m_main_procs.begin();
    for (auto node_iter = m_sec_cfg.m_cfg.begin();
         node_iter < m_sec_cfg.m_cfg.end();
         ++node_iter) {

        if (proc_iter < m_call_graph.m_main_procs.end()
            && ((*proc_iter).estimatedEndAddr()
                <= (*node_iter).getCandidateStartAddr())) {
            proc_iter++;
        }
        if ((*node_iter).isData()) {
            continue;
        }
        if (!(*node_iter).isAssignedToProcedure()) {
            auto proc_node = m_call_graph.insertProcedure
                ((*node_iter).getCandidateStartAddr(),
                 &(*node_iter),
                 ICFGProcedureType::kIndirectlyCalled);
            if (proc_iter < m_call_graph.m_main_procs.end()) {
                proc_node->m_estimated_end_addr =
                    (*proc_iter).estimatedEndAddr();
            } else {
                proc_node->m_estimated_end_addr = m_call_graph.sectionEndAddr();
            }
            buildProcedure(*proc_node);
        }
    }
    m_call_graph.buildCallGraph();
    // TODO: an entry node with two different entry addresses should be split to
    // two procedures.
    // TODO: a final pass over all procedures to (1) properly classify
    // tail-calls and overlap,call_node (2) backtrack from invalid LR.
}

void SectionDisassemblyAnalyzerARM::buildProcedure
    (ICFGNode &proc_node) noexcept {
    assert(proc_node.entryAddr() < proc_node.m_estimated_end_addr
               && "Invalid end address");
    if (proc_node.entryAddr() % 4 != 0) {
        proc_node.m_entry_addr += 2;
        proc_node.entryNode()->setCandidateStartAddr
            (proc_node.entryNode()->getCandidateStartAddr() + 2);
    }
    if (!proc_node.entryNode()->isCall() &&
        !proc_node.entryNode()->maximalBlock()->branchInfo().isDirect()) {
        if (m_analyzer.isReturnToCaller
            (proc_node.entryNode()->maximalBlock()->branchInstruction())) {
            proc_node.m_exit_nodes.push_back
                ({ICFGExitNodeType::kReturn, proc_node.entryNode()});
            proc_node.setReturnsToCaller(true);
        } else {
            proc_node.m_exit_nodes.push_back
                ({ICFGExitNodeType::kIndirect, proc_node.entryNode()});
        }
        if (!proc_node.entryNode()->maximalBlock()->branchInfo().isConditional()) {
            return;
        }
    }
    proc_node.m_lr_store_idx =
        m_analyzer.getLRStackStoreIndex(proc_node.entryNode());
    if (proc_node.entryNode()->maximalBlock()->branchInfo().isConditional()) {
        traverseProcedureNode(proc_node,
                              proc_node.entryNode()->m_immediate_successor,
                              proc_node.entryNode());
    } else if (proc_node.entryNode()->isCall()) {
        traverseProcedureNode
            (proc_node,
             proc_node.entryNode()->getReturnSuccessorNode(),
             proc_node.entryNode());
    }
    traverseProcedureNode(proc_node,
                          proc_node.entryNode()->m_remote_successor,
                          proc_node.entryNode());
}

void SectionDisassemblyAnalyzerARM::traverseProcedureNode
    (ICFGNode &proc_node,
     CFGNode *cfg_node,
     CFGNode *predecessor) noexcept {

    if (cfg_node == nullptr) {
        // branch to an external procedure
        if (!predecessor->isCall()) {
            proc_node.m_exit_nodes.push_back
                ({ICFGExitNodeType::kTailCall, predecessor});
        }
        return;
    }
    if (!proc_node.isWithinEstimatedAddressSpace
        (cfg_node->getCandidateStartAddr())) {
        // visiting a node outside estimated address space
        if (cfg_node->isProcedureEntry()) {
            if (!predecessor->isCall()) {
                proc_node.m_exit_nodes.push_back
                    ({ICFGExitNodeType::kTailCall, predecessor});
            }
        } else if (cfg_node->isAssignedToProcedure()) {
            proc_node.m_exit_nodes.push_back
                ({ICFGExitNodeType::kOverlap, predecessor});
        } else {
            proc_node.m_exit_nodes.push_back
                ({ICFGExitNodeType::kTailCallOrOverlap, predecessor});
        }
        return;
    }
    if (cfg_node->isAssignedToProcedure()) {
        if (proc_node.id() != cfg_node->procedure_id()) {
            if (cfg_node->isProcedureEntry()) {
                if (!predecessor->isCall()) {
                    proc_node.m_exit_nodes.push_back
                        ({ICFGExitNodeType::kTailCall, predecessor});
                }
            } else {
                proc_node.m_exit_nodes.push_back
                    ({ICFGExitNodeType::kOverlap, predecessor});
            }
        }
        return;
    }
    // if invalid stack manipulation return
    if (proc_node.m_lr_store_idx == 0) {
        proc_node.m_lr_store_idx = m_analyzer.getLRStackStoreIndex(cfg_node);
    } else if (m_analyzer.getLRStackStoreIndex(cfg_node) != 0) {
        // doing double stack allocation for LR is not valid
        proc_node.m_exit_nodes.push_back
            ({ICFGExitNodeType::kInvalidLR, predecessor});
        if (proc_node.m_end_addr < predecessor->maximalBlock()->endAddr()) {
            // set actual end address.
            proc_node.m_end_addr = predecessor->maximalBlock()->endAddr();
            proc_node.m_end_node = cfg_node;
        }
        return;
    }
    // cfg node is now assigned to this procedure
    cfg_node->m_procedure_id = proc_node.id();
    cfg_node->m_role_in_procedure = CFGNodeRoleInProcedure::kBody;
    if (proc_node.m_end_addr < cfg_node->maximalBlock()->endAddr()) {
        // set actual end address.
        proc_node.m_end_addr = cfg_node->maximalBlock()->endAddr();
        proc_node.m_end_node = cfg_node;
    }
    if (cfg_node->maximalBlock()->branchInfo().isConditional()) {
        traverseProcedureNode
            (proc_node, cfg_node->m_immediate_successor, cfg_node);
    } else if (cfg_node->isCall()) {
        traverseProcedureNode
            (proc_node, cfg_node->getReturnSuccessorNode(), cfg_node);
    }
    if (cfg_node->maximalBlock()->branchInfo().isDirect()) {
        traverseProcedureNode
            (proc_node, cfg_node->m_remote_successor, cfg_node);
    } else {
        if (cfg_node->isSwitchStatement()) {
            for (auto &cfg_edge : cfg_node->m_indirect_succs) {
                traverseProcedureNode
                    (proc_node, cfg_edge.node(), cfg_node);
            }
            return;
        }
        if (cfg_node->isCall()) {
            return;
        }
        if (m_analyzer.isReturnToCaller(cfg_node->maximalBlock()->branchInstruction())) {
            // TODO: what if a return doesn't match the same LR?
            // procedures can simply "exit" using sp-relative ldr without return
            proc_node.m_exit_nodes.push_back
                ({ICFGExitNodeType::kReturn, cfg_node});
            proc_node.setReturnsToCaller(true);
        } else {
            proc_node.m_exit_nodes.push_back
                ({ICFGExitNodeType::kIndirect, cfg_node});
        }
    }
}

void SectionDisassemblyAnalyzerARM::recoverDirectCalledProcedures() noexcept {
    for (auto &cfg_node :m_sec_cfg.m_cfg) {
        if (cfg_node.isData()) {
            continue;
        }
        // Sometimes BL/BLX can call non-returning procedures.
        // Hence, we didn't use CFGNode's isCall()
        if (cfg_node.maximalBlock()->branchInfo().isCall()
            && cfg_node.maximalBlock()->branchInfo().isDirect()) {
            // now we only need to recover procedures in this section.
            if (cfg_node.remoteSuccessor() != nullptr) {
                m_call_graph.AddProcedure
                    (cfg_node.maximalBlock()->branchInfo().target(),
                     cfg_node.m_remote_successor,
                     ICFGProcedureType::kDirectlyCalled);
            } else {
                const auto target =
                    cfg_node.maximalBlock()->branchInfo().target();
                if (m_plt_map.isWithinPLTSection(target)) {
                    auto result = m_plt_map.addProcedure(target);
                    auto proc = m_call_graph.insertProcedure
                        (cfg_node.maximalBlock()->branchInfo().target(),
                         cfg_node.m_remote_successor,
                         ICFGProcedureType::kExternal);
                    if (proc != nullptr)
                        proc->setName(result.first);
                    if (result.second) {
                        // if procedure is non-returning
                        cfg_node.setIsCall(false);
                        if (proc != nullptr)
                            proc->setNonReturn(true);
                    }
                }
            }
        }
    }
}

void SectionDisassemblyAnalyzerARM::addCallReturnRelation(CFGNode &node) {
    if (node.maximalBlock()->branchInfo().isCall()) {
        auto succ = findImmediateSuccessor(node);
        if (succ != nullptr) {
            succ->setAsReturnNodeFrom(node);
        }
    }
}
}
