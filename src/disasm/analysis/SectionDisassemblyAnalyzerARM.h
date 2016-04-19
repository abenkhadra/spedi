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
#include "DisassemblyAnalysisHelperARM.h"
#include <unordered_map>

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

private:
    /*
     * Finds a valid basic block in and invalidates all direct predecessors that
     * do not target it.
     */
    void resolveValidBasicBlock(CFGNode &node);
    void addConditionalBranchToCFG(CFGNode &node);
    void resolveOverlapBetweenNodes(CFGNode &node);
    void resolveCFGConflicts
        (CFGNode &node, const std::vector<CFGEdge> &valid_predecessors);
    void resolveLoadConflicts(CFGNode &node);
    void recoverSwitchStatements();
    void shortenToCandidateAddressOrSetToData
        (CFGNode &node, addr_t addr) noexcept;
    bool isConditionalBranchAffectedByNodeOverlap
        (const CFGNode &node) const noexcept;
private:
    // switch table related methods
    /*
     * returns true if given node is definitely not a switch statement.
    */
    bool isNotSwitchStatement(const CFGNode &node) const noexcept;
    struct SwitchTableData {
        SwitchTableData() = default;
        SwitchTableData
            (CFGNode *node, unsigned char table_type, addr_t table_end) :
            m_node{node},
            m_table_type{table_type},
            m_table_end{table_end} {
        }
        CFGNode *m_node;
        unsigned char m_table_type;
        addr_t m_table_end;
    };
    using SwitchData = SectionDisassemblyAnalyzerARM::SwitchTableData;
    SwitchData recoverTBBSwitchTable(CFGNode &node);
    SwitchData recoverTBHSwitchTable(CFGNode &node);
    SwitchData recoverLDRSwitchTable(CFGNode &node);
    void switchTableCleanUp(SwitchTableData &table_data) noexcept;
    int recoverLimitOfSwitchTable(const CFGNode &node) const noexcept;

private:
    // call graph related methods
    using AddrCFGNodePairVec = std::vector<std::pair<addr_t, const CFGNode *>>;
    using AddrICFGNodeMap = std::unordered_map<addr_t, ICFGNode>;
    void buildProcedure(ICFGNode &proc_node) noexcept;
    void traverseProcedureNode
        (ICFGNode &proc_node,
         CFGNode *cfg_node,
         CFGNode *predecessor) noexcept;
    void recoverDirectCalledProcedures() noexcept;
    void buildInnerProcedures(const ICFGNode &proc) noexcept;

private:
    SectionDisassemblyARM *m_sec_disassembly;
    DisassemblyAnalysisHelperARM m_analyzer;
    addr_t m_exec_addr_start;
    addr_t m_exec_addr_end;
    DisassemblyCFG m_sec_cfg;
    DisassemblyCallGraph m_call_graph;
    CFGNode *findSwitchTableTarget
        (addr_t target_addr);
    void addCallReturnRelation(CFGNode &node);
};
}
