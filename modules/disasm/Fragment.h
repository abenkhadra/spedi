//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

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

    friend class MaximalBlock;
    friend class MaximalBlockBuilder;

    Fragment(const Fragment &src) = default;
    Fragment &operator=(const Fragment &src) = default;
    Fragment(Fragment &&src) = default;

    bool isAppendable(const MCInstSmall &inst) const;
    bool isAppendableAt(const addr_t addr) const;
    bool valid() const;
    unsigned int id() const;
    size_t size() const;
    size_t memSize() const;
    addr_t startAddr() const;
    const std::vector<MCInstSmall>& getInstructions() const;
private:
    void append(const MCInstSmall& inst);

private:
    unsigned int m_id;
    size_t m_mem_size;
    std::vector<MCInstSmall> m_insts;
};
}
