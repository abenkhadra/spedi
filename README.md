# Spedi
A speculative disassembler for the variable-size Thumb ISA. Given an 
 ELF file as input, Spedi can:
  
  - Recover correct assembly instructions
  - Recover targets of switch jumps tables
  - Identify procedures in the binary and their call graph. 
  
Spedi works directly on the binary without using any symbol information. We found Spedi 
 to outperform IDA Pro in our experiments. 

# Main idea

Spedi recovers all possible Basic Blocks (BB) available in the binary. BBs that
 share the same jump instruction are group in a Maximal Block (MB). Then, MBs are refined
 using overlap and CFG conflict analysis. More details are available in our upcoming
 CASES'16 paper.


# Usage
Build the project and try it on one of the binaries of our benchmark suite
 available [here]. 

The following command will instruct `spedi`to speculatively disassemble 
 the `.text` section,

```sh
$ ./spedi -t -s -f $FILE > speculative.inst
```
Use the following command to instruct `spedi` to disassemble the `.text` section 
 based on ARM code mapping symbols which provides the ground truth about correct instructions,

```sh
$ ./spedi -t -f $FILE > correct.inst
```
The easiest way to compare both outputs is by using, 

```sh
$ diff -y correct.inst speculative.inst |less
```

Currently, you need to fiddle with `main.cpp` to show results related to 
 switch table and call-graph recovery.
 
# Road map

Spedi is an academic proof-of-concept tool, hence, we won't be continuously improving
  it. However, there are certain features that we have in mind for the future, namely:
  
  - Mixed-mode ARM/Thumb disassembly: the general idea of speculative disassembly provides 
    the framework to do that. Basically, one needs to speculatively disassemble a code region
    twice. One time in Thumb mode, and another time in ARM mode. Later, mode switching instructions
    (mainly `bx` and `blx`) should be analyzed. This [paper] provides more details.
  - ELF Reader: currently our ELF reader is based on [libelfin]. Hence, we inherit some memory leakage issues. 
   Additionally, the reader might crash on binaries with dwarf debug info. These issues needs to be 
   addressed either in upstream or directly here.
  - Support for x86/x64: Thumb and similar RISC-like ISA have limited variability. Basically, instructions can either
  be 2 or 4 bytes width. We need to push the challenge even further by supporting x86/x64. 
    
# Dependencies 

The project depends on [Capstone] disassembly library.              

  [Capstone]: <https://github.com/aquynh/capstone>
  [here]: <https://github.com/abenkhadra/cases16-benchmarks>
  [paper]: <http://dl.acm.org/citation.cfm?id=2555748>
  [libelfin]: <https://github.com/aclements/libelfin>
