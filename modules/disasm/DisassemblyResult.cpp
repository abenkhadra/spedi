//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.


#include "DisassemblyResult.h"

namespace disasm {

DisassemblyResult::DisassemblyResult() :
    m_valid{false},
    m_name{""},
    m_start_addr{0},
    m_size{0} {
}

const std::string &
DisassemblyResult::getName() const {
    return m_name;
}

}
