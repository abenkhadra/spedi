//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "MaximalBlockBuilder.h"
#include <algorithm>
#include <cassert>
#include <array>

namespace disasm{

MaximalBlockBuilder::MaximalBlockBuilder() :
    m_buildable{false},
    m_bb_idx{0},
    m_frag_idx{0},
    m_max_block_idx{0},
    m_last_addr{0} {
}

std::vector<unsigned int>
MaximalBlockBuilder::appendableBasicBlocksAt(const addr_t addr) const {
    // XXX: an instruction can be appendable to multiple basic blocks
    // that share the same last fragment.
    std::vector<unsigned int> result;
    for (auto& frag : m_frags) {
        if (frag.isAppendableAt(addr) ) {
            for(auto& block:m_bblocks){
                // check if fragment is the last in a basic block
                if (block.m_frag_ids.back() == frag.id() ) {
                    result.push_back(block.id());
                }
            }
        }
    }
    return result;
}

void
MaximalBlockBuilder::createBasicBlockWith(const MCInstSmall &inst) {
    m_bblocks.emplace_back(BasicBlock(m_bb_idx));
    m_frags.emplace_back(Fragment(m_frag_idx, inst));
    // link basic block to fragment
    m_bblocks.back().m_frag_ids.push_back(m_frag_idx);
    m_bb_idx++;
    m_frag_idx++;
}

void
MaximalBlockBuilder::createBasicBlockWith(
    const MCInstSmall &inst,
    const BranchInstType br_type,
    const addr_t br_target) {

    createBasicBlockWith(inst);
    m_bblocks.back().m_br_type = br_type;
    m_bblocks.back().m_br_target = br_target;
}

//Fragment*
//MaximalBlockBuilder::findFragment(const unsigned int frag_id) const {
//    Fragment* result = nullptr;
//    for (int idx = 0; idx < m_frags.size(); ++idx) {
//        if (m_frags[idx].id() == frag_id ) {
//            return idx;
//        }
//    }
//    return -1;
//}
//
//BasicBlock*
//MaximalBlockBuilder::findBasicBlock(const unsigned int bb_id) const {
//    BasicBlock* result = nullptr;
//    std::vector<BasicBlock>::iterator block;
//    for (block = m_bblocks.begin(); block < m_bblocks.end(); block++) {
//        if (block->id() == bb_id ) {
//            result = &(*block);
//            break;
//        }
//    }
//    return result;
//}

MaximalBlock MaximalBlockBuilder::build() {
    MaximalBlock result{m_max_block_idx};
    m_max_block_idx++;

    if (!m_buildable)
        // return an invalid maximal block!
        return result;

    unsigned int frag_idx = 0;
    unsigned int bb_idx = 0;

    std::array<int, 15> frag_id_map;
    assert(m_frags.size() < 15 && "Max size of frag_id_map exceeded!!!");
    frag_id_map.fill(-1);

    // copy valid BBs to result
    std::copy_if(m_bblocks.begin(), m_bblocks.end(),
                 std::back_inserter(result.m_bblocks),
                 [&](const BasicBlock &temp) { return temp.valid(); });
    // TODO: defragment consecutive getFragments that belong to only one BB.
    // TODO: set a memory size to the maximal block equal to the size of its biggest BB
    for (auto& block:result.m_bblocks) {
        // fixed ids for faster lookup
        block.m_id = bb_idx;
        bb_idx++;
        // Fix id mapping for each block
        for (auto id: block.m_frag_ids) {
            if (frag_id_map[id] == -1) {
                // mapping the new frag_id
                frag_id_map[id] = frag_idx;
                // id was not found in map
                std::vector<Fragment>::iterator iter;
                for (iter = m_frags.begin(); iter < m_frags.end(); ++iter) {
                    if ((*iter).id() == id) break;
                }
                assert((iter != m_frags.end()) && "Fragment was not found!!");
                result.m_frags.push_back(*iter);
                result.m_frags.back().m_id = frag_idx;
                block.m_frag_ids[id] = frag_idx;
                frag_idx++;
            } else {
                block.m_frag_ids[id] =
                    static_cast<unsigned int>(frag_id_map[id]);
            }
        }
    }
    return result;
}

bool MaximalBlockBuilder::reset() {

    m_buildable = false;
    m_bb_idx = 0;

    std::vector<BasicBlock> temp_bb;
    std::vector<BasicBlock>::iterator it_block;
    std::vector<Fragment> temp_frag;
    std::vector<Fragment>::iterator it_frag;

    for (it_frag = m_frags.begin(); it_frag < m_frags.end() ; ++it_frag) {
        // XXX: overlap distance between fragments should be double checked.
        if ((*it_frag).startAddr() + (*it_frag).memSize() - m_last_addr == 2) {
            temp_frag.push_back(*it_frag);
        }        
    }

    for (const BasicBlock &block : m_bblocks) {
        // only non-valid basic blocks can be considered as a partial result
        //  for next MB.
        if (!block.valid()) {
            for (auto& frag : temp_frag) {
                if (frag.id() == block.m_frag_ids.back()) {
                    temp_bb.push_back(block);
                    temp_bb.back().m_id = m_bb_idx;
                    m_bb_idx++;
                    break;
                }
            }
        }
    }
    assert(temp_bb.size() < 2 && "More than two overlaping BBs found!!");
    if (temp_bb.size() == 0) {
        // no overlap was detected, resetting data structures.
        m_bblocks.clear();
        m_frags.clear();
        m_frag_idx = 0;
        return true;
    } else {
        // For variable-length RISC it's impossible to have more than 2 overlapping
        //  BBs. For x86, it's extremely unlikely.
        m_bblocks.clear();
        m_bblocks.push_back(temp_bb.back());
        // XXX: we will leave m_frags intact for the moment.
//        for (auto id : m_bblocks.back().m_frag_ids) {
//            current = findFragment(id);
//            current->m_id = m_frag_idx;
//            temp_frag.push_back(*current);
//            m_frag_idx++;
//        }
//        m_frags.clear();
//        m_frags.swap(temp_frag);
        return false;
    }
}

void MaximalBlockBuilder::append(const MCInstSmall &inst) {

    if (m_bblocks.size() == 0) {
        createBasicBlockWith(inst);
        return;
    }

    if (m_bblocks.size() == 1) {
        // XXX: in case we have only one basic block then the
        // last fragment in that block should be the appendable fragment.
        if (m_frags.back().isAppendable(inst)) {
            m_frags.back().append(inst);
            return;
        } else {
            createBasicBlockWith(inst);
            return;
        }
    }

    std::vector<BasicBlock*> append_blocks;
    std::vector<Fragment*> append_frag;

    // find appendable basic blocks
    bool is_last; // used for invariant checking
    for (auto& frag : m_frags) {
        if (frag.isAppendableAt(inst.addr()) ) {
            is_last = false;
            // XXX: is it reliable to store pointers here?
            append_frag.push_back(&frag);
            for(auto& block:m_bblocks){
                // check if fragment is the last in a basic block
                if (block.m_frag_ids.back() == frag.id() ) {
                    is_last = true;
                    append_blocks.push_back(&block);
                }
            }
            assert(is_last && "Found appendable fragment that is not last!!");
        }
    }
    switch (append_frag.size()) {
        case 0:
            createBasicBlockWith(inst);
            break;
        case 1:
            append_frag.back()->append(inst);
            break;
        default:
            // create a new fragment with the given instruction
            m_frags.emplace_back(Fragment(m_frag_idx, inst));
            // link BBs to new fragment
            for (auto& block : append_blocks) {
                block->m_frag_ids.push_back(m_frag_idx);
            }
            m_frag_idx++;
        break;
    }
}

void MaximalBlockBuilder::append(const MCInstSmall &inst,
                                 const BranchInstType br_type,
                                 const addr_t br_target) {
    m_buildable = true;
    if (m_bblocks.size() == 0) {
        createBasicBlockWith(inst, br_type, br_target);
        return;
    }
    if (m_bblocks.size() == 1) {
        if (m_frags.back().isAppendable(inst)) {
            m_bblocks.back().m_br_type = br_type;
            m_bblocks.back().m_br_target = br_target;
            m_frags.back().append(inst);
            return;
        } else {
            createBasicBlockWith(inst, br_type, br_target);
            return;
        }
    }

    std::vector<BasicBlock*> append_blocks(m_bblocks.size());
    std::vector<Fragment*> append_frag(m_frags.size());
    // find appendable basic blocks
    bool is_last; // used for invariant checking
    for (auto& frag : m_frags) {
        if (frag.isAppendableAt(inst.addr()) ) {
            is_last = false;
            append_frag.push_back(&frag);
            for(auto& block:m_bblocks){
                // check if fragment is the last in a basic block
                if (block.m_frag_ids.back() == frag.id() ) {
                    is_last = true;
                    append_blocks.push_back(&block);
                }
            }
            assert(is_last && "Found appendable fragment that is not last!!");
        }
    }
    switch (append_frag.size()){
        case 0:
            createBasicBlockWith(inst, br_type, br_target);
            break;
        case 1:
            append_frag.back()->append(inst);
            // there can be multiple BBs sharing an appendable fragment
            for (auto& block : append_blocks) {
                block->m_br_type = br_type;
                block->m_br_target = br_target;
            }
            break;
        default:
            // create a new fragment with the given instruction
            m_frags.emplace_back(Fragment(m_frag_idx, inst));
            for (auto& block : append_blocks) {
                block->m_frag_ids.push_back(m_frag_idx);
                block->m_br_type = br_type;
                block->m_br_target = br_target;
            }
            m_frag_idx++;
            break;
    }
    m_last_addr = inst.addr() + inst.size();
}
}
