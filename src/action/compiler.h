// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_COMPILER_H
#define ZEN_ACTION_COMPILER_H

#include "runtime/evm_module.h"
#include "runtime/module.h"

namespace zen::action {

void performJITCompile(runtime::Module &Mod);
void performEVMJITCompile(runtime::EVMModule &Mod);

} // namespace zen::action

#endif // ZEN_ACTION_COMPILER_H
