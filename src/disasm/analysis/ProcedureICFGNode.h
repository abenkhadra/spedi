//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include <vector>

namespace disasm {

class BlockCFGNode;

/**
 * ProcedureICFGNode
 */
class ProcedureICFGNode {
public:
    /**
     * Construct a ProcedureICFGNode that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    ProcedureICFGNode() = default;
    virtual ~ProcedureICFGNode() = default;
    ProcedureICFGNode(const ProcedureICFGNode &src) = default;
    ProcedureICFGNode &operator=(const ProcedureICFGNode &src) = default;
    ProcedureICFGNode(ProcedureICFGNode &&src) = default;

private:
    std::vector<BlockCFGNode *> m_blocks;

};
}
