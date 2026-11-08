from pathlib import Path
import shutil,subprocess
p=Path('src/compiler/compiler.cpp');original=p.read_text();s=original
s=s.replace('#include "compiler/compiler.h"','#include "compiler/compiler.h"\n#include <chrono>\n#include <cstdio>\n#include <cstdlib>',1)
a=s.index('LazyJITCompiler::compileFunction(');b=s.index('\nvoid LazyJITCompiler::compileFunctionInBackgroud',a);body=s[a:b];body=body.replace('  LazyInitialRAPolicy::Timer BudgetTimer','  const auto ResearchStart = std::chrono::steady_clock::now();\n  LazyInitialRAPolicy::Timer BudgetTimer',1)
needle='  if (LoopGreedy)\n    ForegroundLoopGreedyCount'
insert='''  if (const char *Dir = std::getenv("DTVM_RESEARCH_NATIVE_DIR")) {
    const auto Ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - ResearchStart).count();
    const unsigned RealIdx = FuncIdx + WasmMod->getNumImportFunctions();
    const bool Greedy = !DisableGreedyRA || LoopGreedy;
    char Path[4096];
    std::snprintf(Path, sizeof(Path), "%s/func-%u-%d-%llx.bin", Dir, RealIdx,
                  Greedy, (unsigned long long)(uintptr_t)Ctx.CodePtr);
    if (FILE *Out = std::fopen(Path, "wb")) {
      std::fwrite(Ctx.CodePtr, 1, Ctx.CodeSize, Out);
      std::fclose(Out);
    }
    std::fprintf(stderr, "NATIVE %u %d %llx %zu %llu\\n", RealIdx, Greedy,
        (unsigned long long)(uintptr_t)Ctx.CodePtr, size_t(Ctx.CodeSize),
        (unsigned long long)Ns);
  }
'''
assert body.count(needle)==1;body=body.replace(needle,insert+needle);s=s[:a]+body+s[b:]
try:
 p.write_text(s)
 with open('work/combined-optimization/v2/build-diagnostic.log','w') as f:subprocess.run(['cmake','--build','work/build-baseline','--target','dtvm','-j','2'],stdout=f,stderr=subprocess.STDOUT,check=True)
 shutil.copy2('work/build-baseline/dtvm','work/combined-optimization/v2/dtvm-combined-diagnostic')
finally:p.write_text(original)
with open('work/combined-optimization/v2/build-restore-production.log','w') as f:subprocess.run(['cmake','--build','work/build-baseline','--target','dtvm','-j','2'],stdout=f,stderr=subprocess.STDOUT,check=True)
assert Path('work/build-baseline/dtvm').read_bytes()==Path('work/combined-optimization/v2/dtvm-combined').read_bytes()
