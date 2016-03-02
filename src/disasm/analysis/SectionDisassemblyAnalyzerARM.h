//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "DisassemblyCFG.h"
#include "DisassemblyCallGraph.h"
#include "MCInstAnalyzerARM.h"

namespace disasm {

class SectionDisassemblyARM;
class RawInstAnalyzer;

/**
 * SectionDisassemblyAnalyzerARM
 */
class SectionDisassemblyAnalyzerARM {
public:
    SectionDisassemblyAnalyzerARM() = delete;
    SectionDisassemblyAnalyzerARM
        (SectionDisassemblyARM *sec_disasm,
         const std::pair<addr_t, addr_t> &exec_region);

    virtual ~SectionDisassemblyAnalyzerARM() = default;
    SectionDisassemblyAnalyzerARM
        (const SectionDisassemblyAnalyzerARM &src) = default;
    SectionDisassemblyAnalyzerARM
        &operator=(const SectionDisassemblyAnalyzerARM &src) = default;
    SectionDisassemblyAnalyzerARM
        (SectionDisassemblyAnalyzerARM &&src) = default;

    void buildCFG();
    void refineCFG();
    void buildCallGraph();
    /*
     * Search in CFG to find direct successor
     */
    CFGNode *findImmediateSuccessor(const CFGNode &cfg_node) noexcept;
    /*
     * Search in CFG to find remote successor matching target
     */
    CFGNode *findRemoteSuccessor(addr_t target) noexcept;

    void RefineMaximalBlocks(const std::vector<addr_t> &known_code_addrs);
    bool isValidCodeAddr(addr_t addr) const noexcept;
    const DisassemblyCFG &getCFG() const noexcept;

    /*
     * precondition: given instruction is PC-relative load
     */
    CFGNode *findCFGNodeAffectedByLoadStartingFrom
        (const CFGNode &node, addr_t target) noexcept;
    /*
     * returns the sum of instruction count of all predecessors in addition to
     * instruction count of current node.
     */
    size_t calculateNodeWeight(const CFGNode *node) const noexcept;

    /*
     * returns the sum of instruction count of all predecessors that are
     * not of type data in addition to instruction count of given basic block.
     */
    size_t calculateBasicBlockWeight
        (const CFGNode &node, const BasicBlock &basic_block) const noexcept;

    /*
     * returns true if given node is definitely not a switch statement.
     */
    bool isNotSwitchStatement(const CFGNode &node) const noexcept;

private:
    /*
     * Finds a valid basic block in and invalidates all direct predecessors that
     * do not target it.
     */
    void resolveValidBasicBlock(CFGNode &node);
    void addConditionalBranchToCFG(CFGNode &node);
    void resolveOverlapBetweenCFGNodes(CFGNode &node);
    void resolveCFGConflicts
        (CFGNode &node, const std::vector<CFGEdge> &valid_predecessors);
    void resolveLoadConflicts(CFGNode &node);
    void resolveSwitchStatements(CFGNode &node);
    void shortenToCandidateAddressOrSetToData
        (CFGNode &node, addr_t addr) noexcept;
    bool isConditionalBranchAffectedByNodeOverlap
        (const CFGNode &node) const noexcept;
    void recoverTBBSwitchTable(CFGNode &node);
    void recoverTBHSwitchTable(CFGNode &node);
    void recoverLDRSwitchTable(CFGNode &node, unsigned offset);
    void switchTableCleanUp
        (CFGNode &node, bool is_bounded, CFGNode *current_node);
private:
    // call graph related methods
    void buildProcedureStartingFrom(CFGNode &entry_node);

private:
    SectionDisassemblyARM *m_sec_disassembly;
    MCInstAnalyzerARM m_analyzer;
    addr_t m_exec_addr_start;
    addr_t m_exec_addr_end;
    DisassemblyCFG m_sec_cfg;
    DisassemblyCallGraph m_call_graph;
    CFGNode *findSwitchTargetStartingFromNode
        (const CFGNode &node, addr_t target_addr);
};
}
