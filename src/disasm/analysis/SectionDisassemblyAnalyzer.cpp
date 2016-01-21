//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

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
    auto block_it = m_sec_disassembly->getMaximalBlocks().begin();
    for (; block_it < m_sec_disassembly->getMaximalBlocks().end(); ++block_it) {

        m_cfg.emplace_back(MaximalBlockCFGNode(&(*block_it)));
        if ((*block_it).getBranch().isDirect()
            && !isValidCodeAddr((*block_it).getBranch().getTarget())) {
            // a branch to an address outside of executable code
            (*block_it).setType(MaximalBlockType::kData);
            continue;
        }
        if ((*block_it).getBranch().isConditional()) {
            auto succ = getDirectSuccessor((*block_it));
            if (succ != nullptr) {
                m_cfg.back().setDirectSuccessor(succ);
            } else {
                // a conditional branch without a direct successor is data
                (*block_it).setType(MaximalBlockType::kData);
            }
        }
        if ((*block_it).getBranch().isDirect()) {
            auto branch_target = (*block_it).getBranch().getTarget();
            if (!m_sec_disassembly->isWithinSectionAddressSpace(branch_target)) {
                // a valid direct branch can happen to an executable section
                // other than this section.
                continue;
            }
            auto succ =
                getRemoteSuccessor((*block_it), branch_target);
            if (succ != nullptr) {
                m_cfg.back().setRemoteSuccessor(succ);
            } else {
                // a direct branch that doesn't target an MB is data
                (*block_it).setType(MaximalBlockType::kData);
            }
        }
    }
    m_valid = true;
}

bool SectionDisassemblyAnalyzer::isValidCodeAddr(addr_t addr) const {
    // XXX: validity should consider alignment of the address
    return (m_exec_start <= addr) && (addr < m_exec_end);
}

MaximalBlock *
SectionDisassemblyAnalyzer::getDirectSuccessor(const MaximalBlock &block) const {
    if (m_sec_disassembly->isLast(block)) {
        return nullptr;
    }
    auto direct_succ =
        m_sec_disassembly->ptrToMaximalBlockAt(block.getId() + 1);
    if (direct_succ->isInstructionAddress(block.getEndAddr())) {
        return direct_succ;
    }
    // ideally, a direct successor should be the next MaximalBlock but that
    // might not hold in the case of overlap
    if (m_sec_disassembly->isLast(*direct_succ)) {
        return nullptr;
    }
    auto direct_succ2 =
        m_sec_disassembly->ptrToMaximalBlockAt(block.getId() + 2);
    if (direct_succ2->isInstructionAddress(block.getEndAddr())) {
        return direct_succ2;
    }
    printf("ERROR10: Direct successor was not found\n");
    return nullptr;
}

MaximalBlock *
SectionDisassemblyAnalyzer::getRemoteSuccessor(const MaximalBlock &block,
                                               const addr_t &target) const {
    // binary search to find the remote MB that is targeted.
    // assuming that MBs are sorted in an associative container.
    if (target < m_exec_start || target > m_exec_end) {
        return nullptr;
    }
    size_t first = 0;
    size_t last = m_sec_disassembly->maximalBlockCount() - 1;
    size_t middle = (first + last)/2;
//    // direct branches usually happen to a nearby address
//    if (block.getAddrOfLastInst() < target) {
//        middle = block.getId() + 100;
//        if (middle > last) {
//            middle = last - 50;
//        }
//    } else {
//        if (block.getId() > 100) {
//            middle = block.getId() - 100;
//        } else {
//            middle = first + 50;
//        }
//    }
    // classical binary search
    while (first <= last) {
        if (m_sec_disassembly->maximalBlockAt(middle).getAddrOfLastInst()
            < target) {
            first = middle + 1;
        } else {
            if (m_sec_disassembly->
                maximalBlockAt(middle).isInstructionAddress(target)) {
                return m_sec_disassembly->ptrToMaximalBlockAt(middle);
            }
            last = middle - 1;
        }
        middle = (first + last) / 2;
    }
    return nullptr;
}
}