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
    auto block_iter = m_sec_disassembly->getMaximalBlocks().begin();
    for (; block_iter < m_sec_disassembly->getMaximalBlocks().end();
           ++block_iter) {

        m_cfg.emplace_back(MaximalBlockCFGNode(&(*block_iter)));
        if ((*block_iter).getBranch().isDirect()
            && !isValidCodeAddr((*block_iter).getBranch().getTarget())) {
            // a branch to an address outside of executable code
            (*block_iter).setType(MaximalBlockType::kData);
            continue;
        }
        if ((*block_iter).getBranch().isConditional()) {
            auto succ = getDirectSuccessor((*block_iter));
            if (succ != nullptr) {
                m_cfg.back().setDirectSuccessor(succ);
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
                getRemoteSuccessor((*block_iter), branch_target);
            if (succ != nullptr) {
                m_cfg.back().setRemoteSuccessor(succ);
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

MaximalBlock *
SectionDisassemblyAnalyzer::getDirectSuccessor(const MaximalBlock &block) const {
    if (m_sec_disassembly->isLast(block)) {
        return nullptr;
    }
    auto direct_succ =
        m_sec_disassembly->ptrToMaximalBlockAt(block.getId() + 1);
    if (direct_succ->isInstructionAddress(block.endAddr())) {
        return direct_succ;
    }
    // ideally, a direct successor should be the next MaximalBlock but that
    // might not hold in the case of overlap
    if (m_sec_disassembly->isLast(*direct_succ)) {
        return nullptr;
    }
    auto direct_succ2 =
        m_sec_disassembly->ptrToMaximalBlockAt(block.getId() + 2);
    if (direct_succ2->isInstructionAddress(block.endAddr())) {
        return direct_succ2;
    }
    printf("ERROR10: Direct successor was not found\n");
    return nullptr;
}

MaximalBlock *
SectionDisassemblyAnalyzer::getRemoteSuccessor(const MaximalBlock &block,
                                               addr_t target) const {
    // binary search to find the remote MB that is targeted.
    // assuming that MBs are sorted in an associative container.
    if (target < m_exec_start || target > m_exec_end) {
        return nullptr;
    }
    size_t first = 0;
    size_t last = m_sec_disassembly->maximalBlockCount() - 1;
    size_t middle = (first + last) / 2;
    while (last - middle > 2) {
        if (target >
            m_sec_disassembly->maximalBlockAt(middle).addrOfFirstInst()) {
            first = middle;
        } else {
            last = middle;
        }
        middle = (first + last) / 2;
    }
    // We do a linear search here since its more resilient to overlap
    for (size_t i = first; i <= last; ++i) {
        if (m_sec_disassembly->maximalBlockAt(i).isInstructionAddress(target)) {
            return m_sec_disassembly->ptrToMaximalBlockAt(i);
        }
    }
    return nullptr;
}
}