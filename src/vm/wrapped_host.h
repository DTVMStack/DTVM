// wrapped_host.h
#ifndef WRAPPED_HOST_H
#define WRAPPED_HOST_H

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>

// Wrapper class for C evmc interfaces
class WrappedHost : public evmc::Host {
private:
  const evmc_host_interface *HostInterface;
  evmc_host_context *HostContext;

public:
  WrappedHost(const evmc_host_interface *interface = nullptr,
              evmc_host_context *context = nullptr) noexcept
      : HostInterface(interface), HostContext(context) {}

  void reinitialize(const evmc_host_interface *interface,
                    evmc_host_context *context) {
    HostInterface = interface;
    HostContext = context;
  }

  const evmc_host_interface *getInterface() const noexcept {
    return HostInterface;
  }

  evmc_host_context *getContext() const noexcept { return HostContext; }

  bool account_exists(const evmc::address &Addr) const noexcept override {
    return HostInterface->account_exists(HostContext, &Addr);
  }

  evmc::bytes32 get_storage(const evmc::address &Addr,
                            const evmc::bytes32 &Key) const noexcept override {
    return HostInterface->get_storage(HostContext, &Addr, &Key);
  }

  evmc_storage_status
  set_storage(const evmc::address &Addr, const evmc::bytes32 &Key,
              const evmc::bytes32 &Value) noexcept override {
    return HostInterface->set_storage(HostContext, &Addr, &Key, &Value);
  }

  evmc::uint256be
  get_balance(const evmc::address &Addr) const noexcept override {
    return HostInterface->get_balance(HostContext, &Addr);
  }

  size_t get_code_size(const evmc::address &Addr) const noexcept override {
    return HostInterface->get_code_size(HostContext, &Addr);
  }

  evmc::bytes32
  get_code_hash(const evmc::address &Addr) const noexcept override {
    return HostInterface->get_code_hash(HostContext, &Addr);
  }

  size_t copy_code(const evmc::address &Addr, size_t CodeOffset,
                   uint8_t *BufferData,
                   size_t BufferSize) const noexcept override {
    return HostInterface->copy_code(HostContext, &Addr, CodeOffset, BufferData,
                                    BufferSize);
  }

  bool selfdestruct(const evmc::address &Addr,
                    const evmc::address &Beneficiary) noexcept override {
    return HostInterface->selfdestruct(HostContext, &Addr, &Beneficiary);
  }

  evmc::Result call(const evmc_message &Msg) noexcept override {
    evmc_result result = HostInterface->call(HostContext, &Msg);
    return evmc::Result(result);
  }

  evmc_tx_context get_tx_context() const noexcept override {
    return HostInterface->get_tx_context(HostContext);
  }

  evmc::bytes32 get_block_hash(int64_t BlockNumber) const noexcept override {
    return HostInterface->get_block_hash(HostContext, BlockNumber);
  }

  void emit_log(const evmc::address &Addr, const uint8_t *Data, size_t DataSize,
                const evmc::bytes32 Topics[],
                size_t NumTopics) noexcept override {
    HostInterface->emit_log(HostContext, &Addr, Data, DataSize,
                            reinterpret_cast<const evmc_bytes32 *>(Topics),
                            NumTopics);
  }

  evmc_access_status
  access_account(const evmc::address &Addr) noexcept override {
    return HostInterface->access_account(HostContext, &Addr);
  }

  evmc_access_status
  access_storage(const evmc::address &Addr,
                 const evmc::bytes32 &Key) noexcept override {
    return HostInterface->access_storage(HostContext, &Addr, &Key);
  }

  evmc::bytes32
  get_transient_storage(const evmc::address &Addr,
                        const evmc::bytes32 &Key) const noexcept override {
    return HostInterface->get_transient_storage(HostContext, &Addr, &Key);
  }

  void set_transient_storage(const evmc::address &Addr,
                             const evmc::bytes32 &Key,
                             const evmc::bytes32 &Value) noexcept override {
    HostInterface->set_transient_storage(HostContext, &Addr, &Key, &Value);
  }
};

#endif
