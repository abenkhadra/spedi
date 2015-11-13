//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

#include "BCInstSmall.h"
#include <vector>

namespace disasm {
/**
 * Fragment
 */
class Fragment {
public:

    Fragment();
    Fragment(size_t addr);
    virtual ~Fragment() = default;

    Fragment(const Fragment &src) = default;
    Fragment &operator=(const Fragment &src) = default;
    Fragment(Fragment &&src) = default;

    bool isAppendable(const BCInstSmall &inst) const;
    void appendInst(const BCInstSmall &inst);

    bool Valid() const;

    size_t Size() const;
    size_t MemSize() const;

private:
    unsigned int m_id;
    addr_t m_start_addr;
    size_t m_append_addr;
    std::vector<BCInstSmall> m_insts;

};
}



