//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

#include <capstone/capstone.h>
#include <memory>

namespace disasm {
/**
 * BCInst
 * A wrapper around capstone's cs_insn, composition was used instead of
 * inheritance to ensure compatiblity with C API.
 */

class BCInst final{
public:

    BCInst();
    BCInst(cs_insn * instruction);
    ~BCInst() = default;
    BCInst(const BCInst &src) = default;
    BCInst &operator=(const BCInst &src) = default;
    BCInst(BCInst &&src) = default;
    cs_insn * getRawPtr();


private:
    class BCInstDefaultDeleter {
    public:
        void operator()(cs_insn *inst) {
            if (inst->detail != NULL) {
                // memory for instruction details should have been allocated
                // by capstone API.
                free(inst->detail);
            }
            free(inst);
        }
    };
    std::unique_ptr <cs_insn, BCInst::BCInstDefaultDeleter> m_inst;
};

}

