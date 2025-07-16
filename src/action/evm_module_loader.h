#include "action/module_loader.h"

namespace zen::action {

class EVMModuleLoader final {
public:
  explicit EVMModuleLoader(runtime::EVMModule &mod,
                           const std::vector<uint8_t> &data)
      : Mod(mod), Data(data) {}

  void load() {
    if (Data.empty()) {
      throw common::getError(common::ErrorCode::InvalidRawData);
    }
    Mod.Code = Mod.initCode(Data.size());
    std::memcpy(Mod.Code, Data.data(), Data.size());
    Mod.CodeSize = Data.size();
  }

private:
  runtime::EVMModule &Mod;
  const std::vector<uint8_t> Data;
};

} // namespace zen::action
