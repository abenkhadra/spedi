//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "ICFGNode.h"
#include "CFGNode.h"

namespace disasm {

ICFGNode::ICFGNode(unsigned id) :
    m_valid{false},
    m_id{id},
    m_overlap_procedure{nullptr},
    m_overlap_cfg_node{nullptr} {
}

ICFGNode::ICFGNode(unsigned id, CFGNode *entry_node) :
    m_valid{false},
    m_id{id},
    m_overlap_procedure{nullptr},
    m_overlap_cfg_node{nullptr} {
    m_cfg_nodes.push_back(entry_node);
}
}
