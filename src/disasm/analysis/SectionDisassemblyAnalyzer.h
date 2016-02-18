//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "BlockCFGNode.h"
#include "DisassemblyCFG.h"
#include "MaximalBlockAnalyzer.h"

namespace disasm {

class SectionDisassembly;
class RawInstAnalyzer;

/**
 * SectionDisassemblyAnalyzer
 */
class SectionDisassemblyAnalyzer {
public:
    SectionDisassemblyAnalyzer() = delete;
    SectionDisassemblyAnalyzer
        (SectionDisassembly *sec_disasm,
         const std::pair<addr_t, addr_t> &exec_region);

    virtual ~SectionDisassemblyAnalyzer() = default;
    SectionDisassemblyAnalyzer
        (const SectionDisassemblyAnalyzer &src) = default;
    SectionDisassemblyAnalyzer
        &operator=(const SectionDisassemblyAnalyzer &src) = default;
    SectionDisassemblyAnalyzer(SectionDisassemblyAnalyzer &&src) = default;

    void buildCFG();
    void refineCFG();
    /*
     * Search in CFG to find direct successor
     */
    BlockCFGNode *findDirectSuccessor
        (const BlockCFGNode &cfg_node) noexcept;
    /*
     * Search in CFG to find remote successor matching target
     */
    BlockCFGNode *findRemoteSuccessor(addr_t target) noexcept;

    void RefineMaximalBlocks(const std::vector<addr_t> &known_code_addrs);
    bool isValidCodeAddr(addr_t addr) const noexcept;
    const DisassemblyCFG &getCFG() const noexcept;

    /*
     * precondition: given instruction is PC-relative load
     */
    BlockCFGNode *findCFGNodeAffectedByLoadStartingFrom
        (const BlockCFGNode &node, addr_t target) noexcept;

    size_t calculateNodeWeight(const BlockCFGNode *node) const noexcept;

private:
    /*
     * Finds a valid basic block in and invalidates all direct predecessors that
     * do not target it.
     */
    void resolveValidBasicBlock(BlockCFGNode &node);
    void resolveOverlapBetweenCFGNodes(BlockCFGNode &node);
    void resolveCFGConflicts(BlockCFGNode &node);
    void resolveLoadConflicts(BlockCFGNode &node);
    void shortenToCandidateAddressOrSetToData
        (BlockCFGNode &node, addr_t addr) noexcept;

private:
    SectionDisassembly *m_sec_disassembly;
    MaximalBlockAnalyzer m_analyzer;
    addr_t m_exec_addr_start;
    addr_t m_exec_addr_end;
    DisassemblyCFG m_sec_cfg;
};
}
