//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "MaximalBlockCFGNode.h"
#include "../SectionDisassembly.h"
#include "SectionDisassemblyCFG.h"

namespace disasm {
/**
 * SectionDisassemblyAnalyzer
 */
class SectionDisassemblyAnalyzer {
public:
    SectionDisassemblyAnalyzer() = delete;
    explicit SectionDisassemblyAnalyzer
        (SectionDisassembly *sec_disasm,
         const std::pair<addr_t, addr_t> &exec_region);
    virtual ~SectionDisassemblyAnalyzer() = default;
    SectionDisassemblyAnalyzer(const SectionDisassemblyAnalyzer &src) = default;
    SectionDisassemblyAnalyzer
        &operator=(const SectionDisassemblyAnalyzer &src) = default;
    SectionDisassemblyAnalyzer(SectionDisassemblyAnalyzer &&src) = default;

    void BuildCFG();
    MaximalBlock *getDirectSuccessor
        (const MaximalBlockCFGNode &block_node) const;
    MaximalBlock *getRemoteSuccessor
        (addr_t target) const;
    void RefineMaximalBlocks();
    void RefineMaximalBlocks(const std::vector<addr_t> &known_code_addrs);
    bool isValidCodeAddr(addr_t addr) const;
    const SectionDisassemblyCFG &getCFG() const;
private:
    SectionDisassembly *m_sec_disassembly;
    addr_t m_exec_start;
    addr_t m_exec_end;
    SectionDisassemblyCFG m_sec_cfg;
};
}



