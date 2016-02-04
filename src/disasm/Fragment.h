//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once

#include "MCInst.h"
#include <vector>

namespace disasm {
/**
 * Fragment
 */
class Fragment {
public:

    explicit Fragment();
    Fragment(unsigned int id);
    virtual ~Fragment() = default;

    friend class MaximalBlock;
    friend class MaximalBlockBuilder;

    Fragment(const Fragment &src) = default;
    Fragment &operator=(const Fragment &src) = default;
    Fragment(Fragment &&src) = default;

    bool valid() const;
    unsigned int id() const;
    size_t instCount() const;
    addr_t startAddr() const;
    const std::vector<MCInst>& getInstructions() const;

private:
    unsigned int m_id;
    std::vector<MCInst *> m_insts;
};
}
