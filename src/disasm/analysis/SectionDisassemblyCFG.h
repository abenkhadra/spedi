//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "MaximalBlockCFGNode.h"

namespace disasm {
/**
 * SectionDisassemblyCFG
 */
class SectionDisassemblyCFG {
public:
    /**
     * Construct a SectionDisassemblyCFG that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    SectionDisassemblyCFG() = default;
    virtual ~SectionDisassemblyCFG() = default;
    SectionDisassemblyCFG(const SectionDisassemblyCFG &src) = default;
    SectionDisassemblyCFG
        &operator=(const SectionDisassemblyCFG &src) = default;
    SectionDisassemblyCFG(SectionDisassemblyCFG &&src) = default;

    MaximalBlockCFGNode *getCFGNodeOf(const MaximalBlock *max_block);
    const MaximalBlockCFGNode &nodeAt(size_t index) const;
    const std::vector<MaximalBlockCFGNode> &getCFG() const;
    /*
     * Valid only after building CFG.
     */
    bool valid() const { return m_valid; }

    friend class SectionDisassemblyAnalyzer;
private:
    bool m_valid;
    std::vector<MaximalBlockCFGNode> m_cfg;
};
}



