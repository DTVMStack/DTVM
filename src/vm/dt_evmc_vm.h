// dt_evmc_vm.h
#ifndef DT_EVMC_VM_H
#define DT_EVMC_VM_H

#include <evmc/evmc.h>
#include <evmc/utils.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates DT VM.
 */
EVMC_EXPORT struct evmc_vm *evmc_create_dtvmapi(void);

/**
 * Returns the number of background JIT compilations triggered so far.
 * Used by tests to verify profile-guided JIT is working.
 */
EVMC_EXPORT uint64_t dtvm_get_jit_trigger_count(struct evmc_vm *vm);

#ifdef __cplusplus
}
#endif

#endif // DT_EVMC_VM_H
