// Copyright (C) 2021-2023 Ant Group Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_COMPILER_H
#define ZEN_ACTION_COMPILER_H

#include "runtime/module.h"

namespace zen::action {

void performJITCompile(runtime::Module &Mod);

} // namespace zen::action

#endif // ZEN_ACTION_COMPILER_H
