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

class CFGNode;

/**
 * ICFGNode
 */
class ICFGNode {
public:
    /**
     * Construct a ICFGNode that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    ICFGNode() = default;
    virtual ~ICFGNode() = default;
    ICFGNode(const ICFGNode &src) = default;
    ICFGNode &operator=(const ICFGNode &src) = default;
    ICFGNode(ICFGNode &&src) = default;

private:
    std::vector<CFGNode *> m_blocks;

};
}
