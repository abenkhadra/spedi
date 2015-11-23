//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once
#include <stddef.h>
#include <stdint.h>

namespace disasm {
// memory address type
using addr_t = uint64_t;

enum class BranchInstType: unsigned short {
    kUnknown = 0,
    kDirect = 1,
    kInDirect = 2,
    kConditional = 4,
    kUnconditional = 8
};
}
