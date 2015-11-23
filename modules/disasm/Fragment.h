//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

#include "MCInstSmall.h"
#include <vector>

namespace disasm {
/**
 * Fragment
 */
class Fragment {
public:

    explicit Fragment();
    Fragment(unsigned int id, size_t addr);
    Fragment(unsigned int id, const MCInstSmall& inst);
    virtual ~Fragment() = default;

    Fragment(const Fragment &src) = default;
    Fragment &operator=(const Fragment &src) = default;
    Fragment(Fragment &&src) = default;

    friend class MaximalBlock;
    friend class MaximalBlockBuilder;

    bool isAppendable(const MCInstSmall &inst) const;
    bool isAppendableAt(const addr_t addr) const;
    bool valid() const;
    unsigned int id() const;
    size_t size() const;
    size_t memSize() const;
    addr_t startAddr() const;

private:
    unsigned int m_id;
    size_t m_size;
    std::vector<MCInstSmall> m_insts;
};
}
