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
#include "MCInstAnalyzer.h"

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
    /*
     * Search in CFG to find direct successor
     */
    BlockCFGNode *findDirectSuccessor
        (const BlockCFGNode &cfg_node) noexcept;
    /*
     * Search in CFG to find remote successor matching target
     */
    BlockCFGNode *findRemoteSuccessor(addr_t target) noexcept;

    void refineCFG();
    void RefineMaximalBlocks(const std::vector<addr_t> &known_code_addrs);
    bool isValidCodeAddr(addr_t addr) const;
    const DisassemblyCFG &getCFG() const noexcept;

private:
    /*
     * Finds a valid basic block in and invalidates all direct predecessors that
     * do not target it.
     */
    void setValidBasicBlock(BlockCFGNode &node);
    void resolveCFGConflict(BlockCFGNode &node);
private:
    SectionDisassembly *m_sec_disassembly;
    MCInstAnalyzer m_analyzer;
    addr_t m_exec_addr_start;
    addr_t m_exec_addr_end;
    DisassemblyCFG m_sec_cfg;
};
}



