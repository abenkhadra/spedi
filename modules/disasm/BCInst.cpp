//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#include "BCInst.h"

namespace disasm {

BCInst::BCInst() :
// Used "malloc" instead of "new" since an instruction can be allocated
    m_inst(static_cast<cs_insn *>(malloc(sizeof(cs_insn))))
{
    // Keep consistency with Capstone's API.
    m_inst->detail = NULL;
}

BCInst::BCInst(cs_insn *inst) :
    m_inst{inst}
{ }

cs_insn *
BCInst::getRawPtr()
{
    return m_inst.get();
}

}

