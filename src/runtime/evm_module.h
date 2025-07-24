#include "runtime/module.h"
#include "evmc/mocked_host.hpp"

namespace zen {

namespace runtime {

class EVMModule final : public BaseModule<EVMModule> {
  friend class RuntimeObjectDestroyer;
  friend class action::EVMModuleLoader;

public:
  static EVMModuleUniquePtr newEVMModule(Runtime &RT,
                                         CodeHolderUniquePtr CodeHolder);

  virtual ~EVMModule();

  uint8_t *Code;
  size_t CodeSize;
  std::unique_ptr<evmc::MockedHost> HostPtr;

private:
  EVMModule(Runtime *RT);
  EVMModule(const EVMModule &Other) = delete;
  EVMModule &operator=(const EVMModule &Other) = delete;
  CodeHolderUniquePtr CodeHolder;

  uint8_t *initCode(size_t Size) { return (uint8_t *)allocateZeros(Size); }
};

} // namespace runtime
} // namespace zen
