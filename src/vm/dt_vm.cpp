
#include "dt_vm.h"
#include "common/enums.h"
#include "common/errors.h"
#include "runtime/config.h"
#include "runtime/evm_instance.h"
#include "runtime/isolation.h"
#include "runtime/runtime.h"
#include "wrapped_host.h"
#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmc/helpers.h>
#include <evmc/instructions.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

using namespace zen::runtime;
using namespace zen::common;

// CRC32 checksum
uint32_t crc32(const uint8_t *Data, size_t Size) {
  static uint32_t Table[256];
  static bool TableInitialized = false;
  if (!TableInitialized) {
    for (uint32_t I = 0; I < 256; ++I) {
      uint32_t C = I;
      for (int J = 0; J < 8; ++J)
        C = (C & 1) ? (0xEDB88320u ^ (C >> 1)) : (C >> 1);
      Table[I] = C;
    }
    TableInitialized = true;
  }
  uint32_t Crc = 0xFFFFFFFFu;
  for (size_t I = 0; I < Size; ++I)
    Crc = Table[(Crc ^ Data[I]) & 0xFFu] ^ (Crc >> 8);
  return Crc ^ 0xFFFFFFFFu;
}

// VM interface for DTVM
struct DTVM : evmc_vm {
  DTVM();
  ~DTVM() {
    for (auto &P : Insts) {
      EVMInstance *Inst = P.second;
      if (Inst && !RT->unloadEVMModule(Inst->getModule())) {
        ZEN_LOG_ERROR("failed to unload EVM module");
      }
      if (Iso && !Iso->deleteEVMInstance(Inst)) {
        ZEN_LOG_ERROR("failed to delete instance");
      }
    }
  }
  RuntimeConfig Config = {.Format = InputFormat::EVM,
                          .Mode = RunMode::MultipassMode};
  std::unique_ptr<Runtime> RT;
  Isolation *Iso = nullptr;
  std::unordered_map<uint32_t, EVMInstance *> Insts;
};

/// The implementation of the evmc_vm::destroy() method.
void destroy(evmc_vm *VMInstance) { delete static_cast<DTVM *>(VMInstance); }

/// The implementation of the evmc_vm::get_capabilities() method.
evmc_capabilities_flagset get_capabilities(evmc_vm * /*instance*/) {
  return EVMC_CAPABILITY_EVM1;
}

/// VM options.
///
/// The implementation of the evmc_vm::set_option() method.
/// VMs are allowed to omit this method implementation.
enum evmc_set_option_result set_option(evmc_vm *VMInstance, const char *Name,
                                       const char *Value) {
  auto *VM = static_cast<DTVM *>(VMInstance);
  if (std::strcmp(Name, "mode") == 0) {
    if (std::strcmp(Value, "interpreter") == 0) {
      VM->Config.Mode = RunMode::InterpMode;
      return EVMC_SET_OPTION_SUCCESS;
    } else if (std::strcmp(Value, "multipass") != 0) {
      return EVMC_SET_OPTION_INVALID_VALUE;
    }
  }
  return EVMC_SET_OPTION_INVALID_NAME;
}

/// The implementation of the evmc_vm::execute() method.
evmc_result execute(evmc_vm *EVMInstance, const evmc_host_interface *Host,
                    evmc_host_context *Context, enum evmc_revision Rev,
                    const evmc_message *Msg, const uint8_t *Code,
                    size_t CodeSize) {
  std::unique_ptr<evmc::Host> ExecHost =
      std::make_unique<WrappedHost>(Host, Context);
  auto *VM = static_cast<DTVM *>(EVMInstance);

  if (!VM->RT) {
    VM->RT = Runtime::newEVMRuntime(VM->Config, ExecHost.get());
  }

  uint32_t CheckSum = crc32(Code, CodeSize);
  auto ModRet = VM->RT->loadEVMModule(std::to_string(CheckSum), Code, CodeSize);
  if (!ModRet) {
    const Error &Err = ModRet.getError();
    ZEN_ASSERT(!Err.isEmpty());
    const auto &ErrMsg = Err.getFormattedMessage(false);
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  EVMModule *Mod = *ModRet;
  VM->Iso = VM->RT->createManagedIsolation();
  if (!VM->Iso) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  auto InstRet = VM->Iso->createEVMInstance(*Mod, 1000000000);
  if (!InstRet) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  auto TheInst = *InstRet;
  VM->Insts[CheckSum] = TheInst;
  evmc_message Message = *Msg;
  evmc::Result Result;
  VM->RT->callEVMMain(*TheInst, Message, Result);

  return Result.release_raw();
}

/// @cond internal
#if !defined(PROJECT_VERSION)
/// The dummy project version if not provided by the build system.
#define PROJECT_VERSION "0.0.0"
#endif
/// @endcond

DTVM::DTVM()
    : evmc_vm{EVMC_ABI_VERSION, "dtvm",    PROJECT_VERSION,
              ::destroy,        ::execute, ::get_capabilities,
              ::set_option} {}
} // namespace

extern "C" evmc_vm *evmc_create_dtvmapi() { return new DTVM; }
