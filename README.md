# Spedi

Spedi is a speculative disassembler for the variable-size Thumb ISA.
Given an ELF file as input, Spedi can:

  - Recover correct assembly instructions.
  - Recover targets of switch jumps tables.
  - Identify functions in the binary and their call graph.

Spedi works directly on the binary without using symbol information. We found Spedi
to outperform IDA Pro in our experiments.

# Idea

Spedi recovers all possible Basic Blocks (BBs) available in the binary. BBs that
 share the same jump instruction are grouped in one Maximal Block (MB). Then, MBs
 are refined  using overlap and CFG conflict analysis.
 Details can be found in our CASES'16 paper "*Speculative disassembly of binary code*".
 The paper is available [here].

# Result summary

<center>
<img src="https://cloud.githubusercontent.com/assets/11852302/19958591/bed340b2-a1a0-11e6-97b0-79e203aa4a2e.png" alt="Instructions" align="middle" width="600px"/>
</center>

Spedi (almost) perfectly recovers assembly instructions from our benchmarks binaries
with 99.96% average. In comparison, IDA Pro has an average of 95.83% skewed by the
relative poor performance on *sha* benchmark.

<center>
<img src="https://cloud.githubusercontent.com/assets/11852302/19958593/bed7920c-a1a0-11e6-8576-65edb12707c5.png" alt="Callgraph" align="middle" width="600px"/>
</center>

Spedi precisely recovers 97.46% of functions on average. That is, it identifies
the correct start address and end address. Compare that to 40.53% average achieved by IDA Pro.

<center>
<img src="https://cloud.githubusercontent.com/assets/11852302/19958592/bed69ee2-a1a0-11e6-98bf-91b4e91ffd7d.png" alt="Disassembly time" align="middle" width="600px"/>
</center>

A nice property of our technique is that it's also fast and scales well with increased
benchmark size. For example, spedi disassembles *du* (50K instructions) in about 150 ms.
Note that there is good room for further optimizations.

# Citing

To cite Spedi in an academic work please use:

```
@inproceedings{BenKhadraSK2016,
 author = {Ben Khadra, M. Ammar and Stoffel, Dominik and Kunz, Wolfgang},
 title = {Speculative Disassembly of Binary Code},
 booktitle = {Proceedings of the International Conference on Compilers, Architectures and Synthesis for Embedded Systems},
 year = {2016},
 location = {Pittsburgh, Pennsylvania},
 articleno = {16},
 doi = {10.1145/2968455.2968505},
 acmid = {2968505},
 publisher = {ACM},
}
```
# Usage
Build the project and try it on one of the binaries in our benchmark suite
 available in this [repository].

The following command will instruct `spedi` to speculatively disassemble
 the `.text` section,

```sh
$ ./spedi -t -s -f $FILE > speculative.inst
```

Use the following command to disassemble the `.text` section
based on ARM code mapping symbols which provides the ground truth about correct instructions,

```sh
$ ./spedi -t -f $FILE > correct.inst
```
The easiest way to compare both outputs is by using,

```sh
$ diff -y correct.inst speculative.inst |less
```

Currently, you need to manually modify `main.cpp` to show results related to
 switch table and call-graph recovery.

# Road map

This tool is an academic proof-of-concept. Currently, it's not on our priority list.
However, there are certain features that we have in mind for the future, namely:

  - **Mixed-mode ARM/Thumb disassembly**. The general idea of speculative disassembly  
  provides the framework to do this.
  Basically, one needs to speculatively disassemble a code region
  twice. One time in Thumb mode, and a second time in ARM mode. Later, mode
  switching instructions (mainly `bx` and `blx`) should be analyzed. This [paper]
  provides some related details.
  - **Support for x86/x64**. Thumb and similar RISC-like ISA have limited variability.
  Basically, instructions can either be 2 or 4 bytes width. We need to push the
  challenge even further by supporting x86/x64. To this end, overlap analysis might
  span more than two MB which complicates things. Current Maximal Block data structure
  is not efficient to do this.
  - **Refactorings**. The code is tightly coupled with our ELF reader. Also, it is
  specific to Thumb ISA. We need to make it more modular to support other ISAs and binary formats.
  - **ELF Reader**: Our ELF reader is based on [libelfin]. We inherit some memory
  leakage issues. Additionally, the reader might crash on binaries with DWARF
  debug info. These issues needs to be addressed either in upstream or directly here.

# Related work

Recently, Andriesse et. al. have been working on `Nucleus`, a tool for function
identification in x64 binaries. Their paper "*Compiler-Agnostic Function Detection in Binaries*"
was accepted at IEEE Euro S&P 2017. They use more or less the same function identification
techniques implemented in Spedi. If you are interested in x64 support, you can
have a look at their [tool].

Note, however, that their tool is based on the assumption that recent x64
compilers allocate jump-table data in `.rodata` section.
That makes instruction recovery significantly easier since it can be done reliably with
linear sweep. In comparison, Spedi handles the more general case of mixed code/data
using speculative disassembly.


# Dependencies

This project depends on [Capstone] disassembly library (v3.0.4).              

  [here]: <http://dx.doi.org/10.1145/2968455.2968505>
  [Capstone]: <https://github.com/aquynh/capstone>
  [repository]: <https://github.com/abenkhadra/cases16-benchmarks>
  [paper]: <http://dl.acm.org/citation.cfm?id=2555748>
  [libelfin]: <https://github.com/aclements/libelfin>
  [tool]: <https://bitbucket.org/vusec/nucleus>
