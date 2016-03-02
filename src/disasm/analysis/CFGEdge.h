//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once

#include <disasm/common.h>
namespace disasm {
enum class CFGEdgeType: unsigned char {
    kDirect,
    kConditional,
    kReturn,
    kSwitchTable,
    kUnknown
};
class CFGNode;
/**
 * CFGEdge
 */
class CFGEdge {
public:
    /**
     * Construct a CFGEdge that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    CFGEdge() : m_target_node{nullptr} { };
    CFGEdge(CFGNode *target_node, addr_t target_addr) :
        m_type{CFGEdgeType::kDirect},
        m_target_node{target_node},
        m_target_addr{target_addr} { };
    CFGEdge(CFGEdgeType type, CFGNode *target_node, addr_t target_addr):
        m_type{type},
        m_target_node{target_node},
        m_target_addr{target_addr} { };
    virtual ~CFGEdge() = default;
    CFGEdge(const CFGEdge &src) = default;
    CFGEdge &operator=(const CFGEdge &src) = default;
    CFGEdge(CFGEdge &&src) = default;

    bool valid() const noexcept {
        return m_target_node != nullptr;
    }
    CFGNode *node() const noexcept {
        return m_target_node;
    }
    addr_t targetAddr() const noexcept {
        return m_target_addr;
    }
    CFGEdgeType type() const noexcept {
        return m_type;
    }
private:
    CFGEdgeType m_type;
    CFGNode *m_target_node;
    addr_t m_target_addr;
};
}
