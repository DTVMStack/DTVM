// dt_vm.h
#ifndef DT_VM_H
#define DT_VM_H

#include <evmc/evmc.h>
#include <evmc/utils.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates DT VM.
 */
EVMC_EXPORT struct evmc_vm *evmc_create_dtvmapi(void);

#ifdef __cplusplus
}
#endif

#endif // DT_VM_H
