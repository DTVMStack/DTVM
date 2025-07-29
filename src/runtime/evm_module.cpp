#include "runtime/evm_module.h"

#include "action/compiler.h"
#include "action/evm_module_loader.h"
#include "common/enums.h"
#include "common/errors.h"
#include "runtime/codeholder.h"
#include "runtime/symbol_wrapper.h"
#include "utils/statistics.h"
#include "utils/wasm.h"
#include <algorithm>
#include <memory>
#include <string>

namespace zen::runtime {

EVMModule::EVMModule(Runtime *RT)
    : BaseModule(RT, ModuleType::EVM), Code(nullptr), CodeSize(0) {
  // do nothing
}

EVMModule::~EVMModule() {
  if (Name) {
    this->freeSymbol(Name);
    Name = common::WASM_SYMBOL_NULL;
  }

  if (Code) {
    deallocate(Code);
  }
}

std::vector<uint8_t> padCode(const uint8_t *code, size_t code_size) {
  // We need at most 33 bytes of code padding: 32 for possible missing all data
  // bytes of PUSH32 at the very end of the code; and one more byte for STOP to
  // guarantee there is a terminating instruction at the code end.
  constexpr auto padding = 32 + 1;
  constexpr uint8_t OP_STOP = 0x00;

  std::vector<uint8_t> padded_code(code_size + padding);

  std::copy(code, code + code_size, padded_code.begin());
  std::fill_n(padded_code.begin() + code_size, padding, OP_STOP);

  return padded_code;
}

EVMModuleUniquePtr EVMModule::newEVMModule(Runtime &RT,
                                           CodeHolderUniquePtr CodeHolder) {
  void *ObjBuf = RT.allocate(sizeof(EVMModule));
  ZEN_ASSERT(ObjBuf);

  auto *RawMod = new (ObjBuf) EVMModule(&RT);
  EVMModuleUniquePtr Mod(RawMod);

  const uint8_t *Data = static_cast<const uint8_t *>(CodeHolder->getData());
  size_t CodeSize = CodeHolder->getSize();

  std::vector<uint8_t> PaddedCode = padCode(Data, CodeSize);

  action::EVMModuleLoader Loader(*Mod, PaddedCode);

  auto &Stats = RT.getStatistics();
  auto Timer = Stats.startRecord(utils::StatisticPhase::Load);

  Loader.load();

  Stats.stopRecord(Timer);

  Mod->CodeHolder = std::move(CodeHolder);

  ZEN_ASSERT(RT.getEVMHost());
  Mod->Host = RT.getEVMHost();

  return Mod;
}

} // namespace zen::runtime
