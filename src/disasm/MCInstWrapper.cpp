//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "MCInstWrapper.h"

namespace disasm {

MCInstWrapper::MCInstWrapper() :
    m_inst(static_cast<cs_insn*>(malloc(sizeof(cs_insn))))
{
    // Keep consistency with Capstone's API.
    m_inst->detail = static_cast<cs_detail*>(malloc(sizeof(cs_detail)));
}

MCInstWrapper::MCInstWrapper(cs_insn *inst) :
    m_inst{inst}
{ }

cs_insn*
MCInstWrapper::rawPtr()
{
    return m_inst.get();
}

bool MCInstWrapper::isValid() const {
    return m_inst != nullptr;
}
}
