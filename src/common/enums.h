// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMMON_ENUMS_H
#define ZEN_COMMON_ENUMS_H

#include "common/defines.h"

namespace zen::common {

enum ExportKind {
#define DEFINE_EXPORT_KIND(NAME, ID, TEXT) EXPORT_##NAME = ID,
#include "common/wasm_defs/export.def"
#undef DEFINE_EXPORT_KIND
}; // enum ImportKind

enum ImportKind {
#define DEFINE_IMPORT_KIND(NAME, ID, TEXT) IMPORT_##NAME = ID,
#include "common/wasm_defs/import.def"
#undef DEFINE_IMPORT_KIND
}; // enum ImportKind

enum NameSectionType : uint8_t {
#define DEFINE_NAME_SUBSECTION_TYPE(NAME, ID) NAMESEC_##NAME = ID,
#include "common/wasm_defs/sectype.def"
#undef DEFINE_NAME_SUBSECTION_TYPE
  NAMESEC_LAST = NAMESEC_TAG
};

enum SectionType : uint8_t {
#define DEFINE_SECTION_TYPE(NAME, ID, TEXT) SEC_##NAME = ID,
#include "common/wasm_defs/sectype.def"
#undef DEFINE_SECTION_TYPE
  SEC_LAST = SEC_DATACOUNT,
};

enum SectionOrder : uint8_t {
#define DEFINE_SECTION_TYPE(NAME, ID, TEXT) SEC_ORDER_##NAME,
#include "common/wasm_defs/sectype.def"
#undef DEFINE_SECTION_TYPE
};

enum Opcode {
#define DEFINE_WASM_OPCODE(NAME, OPCODE, TEXT) NAME = OPCODE,
#include "common/wasm_defs/opcode.def"
#undef DEFINE_WASM_OPCODE
}; // Opcode

// Multi-byte opcode prefix
constexpr uint8_t WASM_PREFIX_FC = 0xFC;

// 0xFC sub-opcodes for bulk memory operations
// Note: These are always defined to allow code to compile even when
// ZEN_ENABLE_BULK_MEMORY is disabled. Runtime checks ensure these
// opcodes are properly rejected when the feature is disabled.
constexpr uint8_t FC_MEMORY_INIT = 0x08;
constexpr uint8_t FC_DATA_DROP = 0x09;
constexpr uint8_t FC_MEMORY_COPY = 0x0A;
constexpr uint8_t FC_MEMORY_FILL = 0x0B;
constexpr uint8_t FC_TABLE_INIT = 0x0C;
constexpr uint8_t FC_ELEM_DROP = 0x0D;
constexpr uint8_t FC_TABLE_COPY = 0x0E;

enum LabelType {
  LABEL_BLOCK,
  LABEL_LOOP,
  LABEL_IF,
  LABEL_FUNCTION,
};

enum class InputFormat {
  WASM = 0,
  EVM,
};

enum class RunMode {
  InterpMode = 0,
  SinglepassMode = 1,
  MultipassMode = 2,
  UnknownMode = 3,
};

} // namespace zen::common

#endif // ZEN_COMMON_ENUMS_H
