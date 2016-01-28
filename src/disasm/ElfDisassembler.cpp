//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "./analysis/DisassemblyCFG.h"
#include "ElfDisassembler.h"
#include "MCInstWrapper.h"
#include "MCParser.h"
#include "MaximalBlockBuilder.h"
#include "ElfData.h"
#include <inttypes.h>
#include <algorithm>

namespace disasm {

ElfDisassembler::ElfDisassembler() : m_valid{false} { }

ElfDisassembler::ElfDisassembler(const elf::elf &elf_file) :
    m_valid{true},
    m_elf_file{&elf_file} {
    m_analyzer.setISA(getElfMachineArch());
}

void
printHex(unsigned char *str, size_t len) {
    unsigned char *c;

    printf("Code: ");
    for (c = str; c < str + len; c++) {
        printf("0x%02x ", *c & 0xff);
    }
    printf("\n");
}

SectionDisassembly ElfDisassembler::disassembleSectionUsingSymbols
    (const elf::section &sec) const {

    // a type_mismatch exception would thrown in case symbol table was not found.
    // We assume that symbols are ordered by their address.
    auto symbols = getCodeSymbolsOfSection(sec);

//    printf("Symbols size is %lu \n", symbols.size());
//
//    for (auto& symbol : symbols) {
//        printf("Type %d, Addrd, 0x%#x \n", symbol.second, symbol.first);
//    }

    size_t start_addr = sec.get_hdr().addr;
    size_t last_addr = start_addr + sec.get_hdr().size;

    MCParser parser{};
    parser.initialize(CS_ARCH_ARM, CS_MODE_THUMB, last_addr);

    const uint8_t *code_ptr = (const uint8_t *) sec.data();

    MCInstWrapper inst;
    cs_insn *inst_ptr = inst.rawPtr();

    printf("Section Name: %s\n", sec.get_name().c_str());

    size_t index = 0;
    size_t address = 0;
    size_t size = 0;
    MaximalBlockBuilder max_block_builder;
    SectionDisassembly result{&sec};

    for (auto &symbol : symbols) {
        index++;
        if (symbol.second == ARMCodeSymbolType::kData) {
            if (index < symbols.size())
                // adjust code_ptr to start of next symbol.
                code_ptr += (symbols[index].first - symbol.first);
            continue;
        }
        address = symbol.first;
        if (index < symbols.size())
            size = symbols[index].first - symbol.first;
        else
            size = last_addr - symbol.first;

        if (symbol.second == ARMCodeSymbolType::kARM) {
            parser.changeModeTo(CS_MODE_ARM);
            m_analyzer.changeModeTo(ISAType::kARM);
        } else {
            // We assume that the value of code symbol type is strictly
            // either Data, ARM, or Thumb.
            parser.changeModeTo(CS_MODE_THUMB);
            m_analyzer.changeModeTo(ISAType::kThumb);
        }

        while (parser.disasm2(&code_ptr, &size, &address, inst_ptr)) {

//            prettyPrintInst(parser.handle(), inst_ptr, false);
            if (m_analyzer.isBranch(inst_ptr)) {
                max_block_builder.appendBranch(inst_ptr);
                result.add(max_block_builder.build());
//                prettyPrintMaximalBlock(result.back());
                if (!max_block_builder.isCleanReset()) {
                    printf("Overlap detected at MaxBlock %u \n",
                           result.back().getId());
                }
//                printf("Direct branch: %d, Conditional: %d  \n",
//                       analyzer.isDirectBranch(inst_ptr),
//                       analyzer.isConditional(inst_ptr));
//                printf("************************************\n");
            } else {
                max_block_builder.append(inst_ptr);
            }
        }
    }
    return result;
}

SectionDisassembly
ElfDisassembler::disassembleSectionbyName(std::string sec_name) const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == sec_name) {
            return disassembleSectionUsingSymbols(sec);
        }
    }
}

SectionDisassembly
ElfDisassembler::disassembleSectionbyNameSpeculative(std::string sec_name) const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == sec_name) {
            return disassembleSectionSpeculative(sec);

        }
    }
}

void
ElfDisassembler::disassembleCodeUsingSymbols() const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            disassembleSectionUsingSymbols(sec);
        }
    }
}

SectionDisassembly
ElfDisassembler::disassembleSectionSpeculative(const elf::section &sec) const {

    printf("Section Name: %s\n", sec.get_name().c_str());
    size_t current = sec.get_hdr().addr;
    size_t last_addr = current + sec.get_hdr().size;
    size_t buf_size = 4;
    const uint8_t *code_ptr = (const uint8_t *) sec.data();

    MCParser parser;
    parser.initialize(CS_ARCH_ARM, CS_MODE_THUMB, last_addr);

    MCInstWrapper inst;
    cs_insn *inst_ptr = inst.rawPtr();

    MaximalBlockBuilder max_block_builder;

    SectionDisassembly result{&sec};
    // we need to maintain the invariant that for whatever MB in the result
    // its start address should be > than the start address of the next MB.
    while (current < last_addr) {
        if (parser.disasm(code_ptr, buf_size, current, inst_ptr)) {
            if (m_analyzer.isValid(inst_ptr)) {
                if (m_analyzer.isBranch(inst_ptr)) {
                    max_block_builder.appendBranch(inst_ptr);
                    result.add(max_block_builder.build());
//                    prettyPrintMaximalBlock(result.back());
//                    if (!max_block_builder.isCleanReset()) {
//                        printf("Overlap detected at MaxBlock %u \n",
//                               result.back().getId());
//                    }
                } else {
                    max_block_builder.append(inst_ptr);
                }
            }
        }
        current += static_cast<unsigned>(m_analyzer.getInstWidth());
        code_ptr += static_cast<unsigned>(m_analyzer.getInstWidth());
    }
    return result;
}

std::vector<SectionDisassembly>
ElfDisassembler::disassembleCodeSpeculative() const {
    std::vector<SectionDisassembly> result;
    for (auto &sec : m_elf_file->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            result.emplace_back(disassembleSectionSpeculative(sec));
        }
    }
    return result;
}

std::vector<std::pair<size_t, ARMCodeSymbolType>>
ElfDisassembler::getCodeSymbolsOfSection(const elf::section &sec) const {

    std::vector<std::pair<size_t, ARMCodeSymbolType>> result;
    // Check for symbol table, if none was found then
    // the instance is invalid.
    elf::section sym_sec = m_elf_file->get_section(".symtab");
    // Returning a valid section means that there was no symbol table
    //  provided in ELF file.
    if (!sym_sec.valid())
        return result;

    size_t start_addr = sec.get_hdr().addr;
    size_t end_addr = start_addr + sec.get_hdr().size;

    // The following can throw a type_mismatch exception in case
    // of corrupted symbol table in ELF.

    for (auto symbol: sym_sec.as_symtab()) {
        size_t value = symbol.get_data().value;
        // we assume that the start addr of each section is available in
        // code symbols.
        if ((start_addr <= value) && (value < end_addr)) {
            if (symbol.get_name() == ARMCodeSymbolVal::kThumb()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbolType::kThumb));

            } else if (symbol.get_name() == ARMCodeSymbolVal::kARM()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbolType::kARM));

            } else if (symbol.get_name() == ARMCodeSymbolVal::kData()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbolType::kData));

            }
        }
    }
    // Symbols are not necessary sorted, this step is required to
    // avoid potential SEGEV.
    std::sort(result.begin(), result.end());
    return result;
}

bool
ElfDisassembler::isSymbolTableAvailable() {
    elf::section sym_sec = m_elf_file->get_section(".symtab");
    // Returning a invalid section means that there was no symbol table
    //  provided in ELF file.

    return sym_sec.valid();
}

ISAType ElfDisassembler::getInitialMode() const {
    if (m_elf_file->get_hdr().entry & 1) return ISAType::kThumb;
    else return ISAType::kARM;
}

const std::pair<addr_t, addr_t>
ElfDisassembler::getExecutableRegion() {
    addr_t start_addr = UINT64_MAX;
    addr_t end_addr = 0;
    for (auto &sec : m_elf_file->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            if (sec.get_hdr().addr < start_addr) {
                start_addr = sec.get_hdr().addr;
            }
            if (end_addr < sec.get_hdr().addr + sec.get_hdr().size) {
                end_addr = sec.get_hdr().addr + sec.get_hdr().size;
            }
        }
    }
    return std::pair<disasm::addr_t, disasm::addr_t>(start_addr, end_addr);
}

ISAType
ElfDisassembler::getElfMachineArch() const {
    switch (static_cast<elf::ElfISA>(m_elf_file->get_hdr().machine)) {
        case elf::ElfISA::kARM :
            return getInitialMode();

        default:
            return ISAType::kUnknown;
    }
}
void ElfDisassembler::prettyPrintCapstoneInst
    (const csh &handle, cs_insn *inst, bool details_enabled) const {

    cs_detail *detail;
    int n;
    printf("0x%" PRIx64 ":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
           inst->address, inst->mnemonic, inst->op_str,
           inst->id, cs_insn_name(handle, inst->id));

    if (!details_enabled) {
        return;
    }
    // print implicit registers used by this instruction
    detail = inst->detail;
    if (detail == NULL) return;

    if (detail->regs_read_count > 0) {
        printf("\tImplicit registers read: ");
        for (n = 0; n < detail->regs_read_count; n++) {
            printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
        }
        printf("\n");
    }

    // print implicit registers modified by this instruction
    if (detail->regs_write_count > 0) {
        printf("\tImplicit registers modified: ");
        for (n = 0; n < detail->regs_write_count; n++) {
            printf("%s ", cs_reg_name(handle, detail->regs_write[n]));
        }
        printf("\n");
    }

    // print the groups this instruction belong to
    if (detail->groups_count > 0) {
        printf("\tThis instruction belongs to groups: ");
        for (n = 0; n < detail->groups_count; n++) {
            printf("%s ", cs_group_name(handle, detail->groups[n]));
        }
        printf("\n");
    }
}

void ElfDisassembler::prettyPrintMaximalBlock
    (const MaximalBlock *mblock) const {
    printf("**************************************\n");
    printf("MB No. %u. Starts at %#6x",
           mblock->getId(),
           static_cast<unsigned> (mblock->addrOfFirstInst()));
    printf(" / BB count. %lu, Total inst count %u: \n",
           mblock->getBasicBlocksCount(), mblock->instructionsCount());

    for (auto &block :mblock->getBasicBlocks()) {
        printf("Basic Block Id %u, inst count %lu\n / ",
               block.id(), block.instCount());
        for (auto addr : mblock->getInstructionAddressesOf(block)) {
            printf(" Inst Addr: %#6x", static_cast<unsigned>(addr));
        }
        printf("\n");
    }
    for (auto &inst :mblock->getAllInstructions()) {
        printf("0x%" PRIx64 ":\t%s\t\t%s ",
               inst.addr(), inst.mnemonic().c_str(), inst.operands().c_str());
        if (inst.condition() != ARM_CC_AL) {
            printf("/ condition: %s",
                   m_analyzer.conditionCodeToString(inst.condition()).c_str());
        }
        printf("\n");
    }
    printf("Direct branch: %d, Conditional: %d",
           mblock->getBranch().isDirect(), mblock->getBranch().isConditional());
    if (mblock->getBranch().isDirect()) {
        printf(", Target: 0x%x",
               static_cast<unsigned>(mblock->getBranch().target()));
    }
    printf("\n");
}

void ElfDisassembler::prettyPrintCFGNode
    (const MaximalBlockCFGNode *cfg_node) const {
    auto mblock = cfg_node->getMaximalBlock();
    printf("**************************************\n");
    printf("MB No. %u, Type: %u. Starts at %#6x",
           mblock->getId(), cfg_node->getType(),
           static_cast<unsigned> (mblock->addrOfFirstInst()));
    printf(" / BB count. %lu, Total inst count %u: \n",
           mblock->getBasicBlocksCount(), mblock->instructionsCount());

    for (auto &block :mblock->getBasicBlocks()) {
        printf("Basic Block Id %u, inst count %lu\n / ",
               block.id(), block.instCount());
        for (auto addr : mblock->getInstructionAddressesOf(block)) {
            printf(" Inst Addr: %#6x", static_cast<unsigned>(addr));
        }
        printf("\n");
    }
    for (auto &inst :mblock->getAllInstructions()) {
        printf("0x%" PRIx64 ":\t%s\t\t%s ",
               inst.addr(), inst.mnemonic().c_str(), inst.operands().c_str());
        if (inst.condition() != ARM_CC_AL) {
            printf("/ condition: %s",
                   m_analyzer.conditionCodeToString(inst.condition()).c_str());
        }
        printf("\n");
    }
    printf("Direct branch: %d, Conditional: %d",
           mblock->getBranch().isDirect(), mblock->getBranch().isConditional());
    if (mblock->getBranch().isDirect()) {
        printf(", Target: 0x%x",
               static_cast<unsigned>(mblock->getBranch().target()));
    }
    printf("\n");
}

void ElfDisassembler::prettyPrintSectionDisassembly
    (const SectionDisassembly *sec_disasm) const {
    for (auto it = sec_disasm->cbegin(); it < sec_disasm->cend(); ++it) {
        prettyPrintMaximalBlock(&(*it));
    }
}

void ElfDisassembler::prettyPrintSectionCFG
    (const DisassemblyCFG *sec_cfg) const {
    for (auto &node :sec_cfg->getCFG()) {
        prettyPrintCFGNode(&node);
    }
}
}
