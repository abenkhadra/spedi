//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once
#include "common.h"
#include <vector>

struct cs_insn;
namespace disasm {

/**
 * BasicBlock
 * a lightweight container for data relevant to basic blocks contained in
 * a maximal block.
 */
class BasicBlock {
public:
    /**
     * Construct a BasicBlock that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    BasicBlock() = delete;
    BasicBlock(size_t id, const cs_insn *inst);
    virtual ~BasicBlock() = default;
    BasicBlock(const BasicBlock &src) = default;
    BasicBlock &operator=(const BasicBlock &src) = default;
    BasicBlock(BasicBlock &&src) = default;
    addr_t addressAt(unsigned index) const;

    friend class MaximalBlock;
    friend class MaximalBlockBuilder;

    size_t id() const;
    bool isValid() const;
    const size_t size() const;

    bool isAppendableBy(const cs_insn *inst) const;
    bool isAppendableAt(const addr_t addr) const;
    size_t instructionCount() const;
    addr_t startAddr() const;
    addr_t endAddr() const;
    const std::vector<addr_t> &getInstructionAddresses() const;
private:
    void append(const cs_insn *inst);

private:
    bool m_valid;
    size_t m_id;
    size_t m_size;
    std::vector<addr_t> m_inst_addrs;
};
}
