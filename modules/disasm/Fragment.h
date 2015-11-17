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

    Fragment();
    Fragment(unsigned int id, size_t addr);
    virtual ~Fragment() = default;

    Fragment(const Fragment &src) = default;
    Fragment &operator=(const Fragment &src) = default;
    Fragment(Fragment &&src) = default;

    bool isAppendable(const MCInstSmall &inst) const;
    void appendInst(const MCInstSmall &inst);

    bool valid() const;

    size_t size() const;
    size_t memSize() const;

private:
    unsigned int m_id;
    addr_t m_start_addr;
    size_t m_size;
    std::vector<MCInstSmall> m_insts;

};
}



