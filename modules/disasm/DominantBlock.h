//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

namespace disasm {
/**
 * DominantBlock
 */
class DominantBlock {
public:
    /**
     */
    DominantBlock() = default;
    virtual ~DominantBlock() = default;
    DominantBlock(const DominantBlock &src) = default;
    DominantBlock &operator=(const DominantBlock &src) = default;
    DominantBlock(DominantBlock &&src) = default;

    bool valid() const { return !!pimpl; }
private:


};
}



