//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#include "MCInst.h"

namespace disasm {

MCInst::MCInst() :
// Used "malloc" instead of "new" since an instruction can be allocated
    m_inst(static_cast<cs_insn*>(malloc(sizeof(cs_insn))))
{
    // Keep consistency with Capstone's API.
    m_inst->detail = static_cast<cs_detail*>(malloc(sizeof(cs_detail)));
}

MCInst::MCInst(cs_insn *inst) :
    m_inst{inst}
{ }

cs_insn *
MCInst::getRawPtr()
{
    return m_inst.get();
}

}

