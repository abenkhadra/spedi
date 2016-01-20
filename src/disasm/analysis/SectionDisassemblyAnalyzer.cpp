//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "SectionDisassemblyAnalyzer.h"
#include <cassert>

namespace disasm {

SectionDisassemblyAnalyzer::SectionDisassemblyAnalyzer(SectionDisassembly *sec_disasm,
                                                       const std::pair<addr_t,
                                                                       addr_t> &exec_region)
    :
    m_sec_disassembly{sec_disasm},
    m_exec_start{exec_region.first},
    m_exec_end{exec_region.second} {

}

void SectionDisassemblyAnalyzer::BuildCFG() {
    m_cfg.reserve(m_sec_disassembly->size());
    for (auto &block :m_sec_disassembly->getMaximalBlocks()) {
        m_cfg.emplace_back(MaximalBlockCFGNode(&block));
        if (block.getBranch().isDirect()
            && !isValidCodeAddr(block.getBranch().getTarget())) {
            block.setType(MaximalBlockType::kData);
            continue;
        }
        if (block.getBranch().isConditional()) {
            auto succ = getDirectSuccessor(block);
            if (succ != nullptr) {
                m_cfg.back().setDirectSuccessor(succ);
            } else {
                // a conditional branch without a direct successor is data
                block.setType(MaximalBlockType::kData);
            }
        }
        if (block.getBranch().isDirect()) {
            auto succ =
                getRemoteSuccessor(block, block.getBranch().getTarget());
            if (succ != nullptr) {
                m_cfg.back().setRemoteSuccessor(succ);
            } else {
                // a direct branch that doesn't target an instruction is data
                block.setType(MaximalBlockType::kData);
            }
        }
    }
    m_valid = true;
}
bool SectionDisassemblyAnalyzer::isValidCodeAddr(const addr_t &addr) const {
    // XXX: validity should consider alignment of the address
    return (m_exec_start <= addr) && (addr < m_exec_end);
}

MaximalBlock *
SectionDisassemblyAnalyzer::getDirectSuccessor(const MaximalBlock &block) const {
    // ideally, a direct successor should be the next MaximalBlock but that
    // might not hold in the case of overlap
    if (m_sec_disassembly->isLast(block)) {
        return nullptr;
    }
    auto
        direct_succ = m_sec_disassembly->ptrToMaximalBlockAt(block.getId() + 1);
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
    assert("Direct successor was not found");
    return nullptr;
}

MaximalBlock *
SectionDisassemblyAnalyzer::getRemoteSuccessor(const MaximalBlock &block,
                                               const addr_t &target) const {
    // binary search to find the remote MB that is targeted.
    if (target < m_exec_start || target > m_exec_end) {
        return nullptr;
    }
    size_t first = 0;
    size_t last = m_sec_disassembly->size() - 1;
    size_t middle = (first + last) / 2;

    while (first <= last) {
        if (m_sec_disassembly->maximalBlockAt(middle).getAddrOfLastInst()
            < target) {
            first = middle + 1;
        } else {
            if (m_sec_disassembly->maximalBlockAt(middle).isInstructionAddress(
                target)) {
                return m_sec_disassembly->ptrToMaximalBlockAt(middle);
            }
            last = middle - 1;
        }
        middle = (first + last) / 2;
    }
    return nullptr;
}
}