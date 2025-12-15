// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "merkle_patricia_trie.h"
#include "host/evm/crypto.h"
#include "utils/rlp_encoding.h"
#include <algorithm>
#include <cassert>
#include <cstring>

namespace zen::evm::mpt {

// Empty node hash (Keccak256 of empty string)
static const std::vector<uint8_t> EmptyNodeHash = {
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45,
    0xe6, 0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c,
    0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21};

namespace {
// Helper functions to check and access variant alternatives
template <typename T> T *getIf(const Node &Node) {
  return std::get_if<T>(&Node);
}

template <typename T> const T *getIf(const std::shared_ptr<Node> &Node) {
  return Node ? std::get_if<T>(Node.get()) : nullptr;
}

// Shared empty node to avoid repeated allocations
const auto EmptyNodePtr = std::make_shared<Node>(EmptyNode{});

} // anonymous namespace

// Nibbles utility functions implementation
namespace nibbles {

std::pair<Nibble, Nibble> fromByte(uint8_t Byte) {
  return {(Byte >> 4) & 0x0F, Byte & 0x0F};
}

Nibbles fromBytes(const std::vector<uint8_t> &Bytes) {
  Nibbles Result;
  Result.reserve(Bytes.size() * 2);

  for (uint8_t Byte : Bytes) {
    auto [High, Low] = fromByte(Byte);
    Result.push_back(High);
    Result.push_back(Low);
  }

  return Result;
}

Nibbles fromString(const std::string &Str) {
  return fromBytes(std::vector<uint8_t>(Str.begin(), Str.end()));
}

std::vector<uint8_t> toPrefixed(const Nibbles &Nibbles, bool IsLeaf) {
  std::vector<uint8_t> Result;

  uint8_t Prefix = 0;
  if (IsLeaf) {
    Prefix += 2; // Set leaf flag
  }

  if (Nibbles.size() % 2 == 1) {
    Prefix += 1; // Set odd flag
    Result.push_back((Prefix << 4) | Nibbles[0]);

    // Process remaining nibbles in pairs
    for (size_t I = 1; I < Nibbles.size(); I += 2) {
      uint8_t Byte = (Nibbles[I] << 4);
      if (I + 1 < Nibbles.size()) {
        Byte |= Nibbles[I + 1];
      }
      Result.push_back(Byte);
    }
  } else {
    Result.push_back(Prefix << 4);

    // Process nibbles in pairs
    for (size_t I = 0; I < Nibbles.size(); I += 2) {
      uint8_t Byte = (Nibbles[I] << 4);
      if (I + 1 < Nibbles.size()) {
        Byte |= Nibbles[I + 1];
      }
      Result.push_back(Byte);
    }
  }

  return Result;
}

std::vector<uint8_t> toBytes(const Nibbles &Nibbles) {
  assert(Nibbles.size() % 2 == 0 && "Nibbles length must be even");

  std::vector<uint8_t> Result;
  Result.reserve(Nibbles.size() / 2);

  for (size_t I = 0; I < Nibbles.size(); I += 2) {
    uint8_t Byte = (Nibbles[I] << 4) | Nibbles[I + 1];
    Result.push_back(Byte);
  }

  return Result;
}

size_t commonPrefixLength(const Nibbles &A, const Nibbles &B) {
  size_t MinLen = std::min(A.size(), B.size());
  size_t I = 0;

  while (I < MinLen && A[I] == B[I]) {
    I++;
  }

  return I;
}

Nibbles subslice(const Nibbles &NibblesData, size_t Start, size_t End) {
  if (End == SIZE_MAX) {
    End = NibblesData.size();
  }

  assert(Start <= End && End <= NibblesData.size());

  return Nibbles(NibblesData.begin() + Start, NibblesData.begin() + End);
}

} // namespace nibbles

std::vector<uint8_t> serialize(const Node &Node) {
  return std::visit(
      [](const auto &N) -> std::vector<uint8_t> {
        using T = std::decay_t<decltype(N)>;

        if constexpr (std::is_same_v<T, EmptyNode>) {
          return {zen::evm::rlp::RLP_OFFSET_SHORT_STRING};
        } else if constexpr (std::is_same_v<T, LeafNode>) {
          std::vector<std::vector<uint8_t>> Items;
          Items.push_back(nibbles::toPrefixed(N.Path, true));
          Items.push_back(N.Value);
          return zen::evm::rlp::encodeList(Items);
        } else if constexpr (std::is_same_v<T, BranchNode>) {
          std::vector<std::vector<uint8_t>> Items;
          for (const auto &Branch : N.Branches) {
            if (isEmpty(*Branch)) {
              Items.push_back({});
            } else {
              auto BranchHash = hash(*Branch);
              if (BranchHash.size() < 32) {
                Items.push_back(serialize(*Branch));
              } else {
                Items.push_back(BranchHash);
              }
            }
          }
          Items.push_back(N.Value.value_or(std::vector<uint8_t>{}));
          return zen::evm::rlp::encodeList(Items);
        } else if constexpr (std::is_same_v<T, ExtensionNode>) {
          std::vector<std::vector<uint8_t>> Items;
          Items.push_back(nibbles::toPrefixed(N.Path, false));
          if (isEmpty(*N.Next)) {
            Items.push_back({});
          } else {
            auto NextHash = hash(*N.Next);
            if (NextHash.size() < 32) {
              Items.push_back(serialize(*N.Next));
            } else {
              Items.push_back(NextHash);
            }
          }
          return zen::evm::rlp::encodeList(Items);
        }
      },
      Node);
}

std::vector<uint8_t> hash(const Node &Node) {
  return std::visit(
      [](const auto &N) -> std::vector<uint8_t> {
        if constexpr (std::is_same_v<std::decay_t<decltype(N)>, EmptyNode>) {
          return EmptyNodeHash;
        } else {
          return zen::host::evm::crypto::keccak256(
              serialize(::zen::evm::mpt::Node(N)));
        }
      },
      Node);
}

LeafNode LeafNode::fromKeyValue(const std::vector<uint8_t> &Key,
                                const std::vector<uint8_t> &Value) {
  return LeafNode(nibbles::fromBytes(Key), Value);
}

BranchNode::BranchNode() {
  // Initialize all branches to empty nodes
  for (auto &Branch : Branches) {
    Branch = EmptyNodePtr;
  }
}

void BranchNode::setBranch(Nibble Index, std::shared_ptr<Node> NodePtr) {
  assert(Index < 16);
  Branches[Index] = std::move(NodePtr);
}

void BranchNode::removeBranch(Nibble Index) {
  assert(Index < 16);
  Branches[Index] = EmptyNodePtr;
}

void BranchNode::setValue(const std::vector<uint8_t> &Val) { Value = Val; }

void BranchNode::removeValue() { Value.reset(); }

bool BranchNode::hasContent() const {
  if (Value.has_value()) {
    return true;
  }

  for (const auto &Branch : Branches) {
    if (!isEmpty(*Branch)) {
      return true;
    }
  }

  return false;
}

size_t BranchNode::branchCount() const {
  size_t Count = 0;
  for (const auto &Branch : Branches) {
    if (!isEmpty(*Branch)) {
      Count++;
    }
  }
  return Count;
}

std::optional<Nibble> BranchNode::getSingleBranch() const {
  std::optional<Nibble> Result;

  for (Nibble I = 0; I < 16; I++) {
    if (!isEmpty(*Branches[I])) {
      if (Result.has_value()) {
        return std::nullopt; // More than one branch
      }
      Result = I;
    }
  }

  return Result;
}

MerklePatriciaTrie::MerklePatriciaTrie() { Root = EmptyNodePtr; }

std::optional<std::vector<uint8_t>>
MerklePatriciaTrie::get(const std::vector<uint8_t> &Key) const {
  Nibbles KeyNibbles = nibbles::fromBytes(Key);
  return getWithPath(Root, KeyNibbles);
}

std::optional<std::vector<uint8_t>>
MerklePatriciaTrie::getWithPath(std::shared_ptr<Node> NodePtr,
                                const Nibbles &Key) const {
  return std::visit(
      [&](const auto &N) -> std::optional<std::vector<uint8_t>> {
        using T = std::decay_t<decltype(N)>;

        if constexpr (std::is_same_v<T, EmptyNode>) {
          return std::nullopt;
        } else if constexpr (std::is_same_v<T, LeafNode>) {
          if (N.Path == Key) {
            return N.Value;
          }
          return std::nullopt;
        } else if constexpr (std::is_same_v<T, BranchNode>) {
          if (Key.empty()) {
            return N.Value;
          }
          Nibble Index = Key[0];
          Nibbles RemainingKey = nibbles::subslice(Key, 1);
          return getWithPath(N.Branches[Index], RemainingKey);
        } else if constexpr (std::is_same_v<T, ExtensionNode>) {
          size_t MatchedLen = nibbles::commonPrefixLength(Key, N.Path);

          if (MatchedLen == N.Path.size()) {
            Nibbles RemainingKey = nibbles::subslice(Key, MatchedLen);
            return getWithPath(N.Next, RemainingKey);
          }
          return std::nullopt;
        }
      },
      *NodePtr);
}

void MerklePatriciaTrie::put(const std::vector<uint8_t> &Key,
                             const std::vector<uint8_t> &Value) {
  Nibbles KeyNibbles = nibbles::fromBytes(Key);
  Root = put(Root, KeyNibbles, Value);
}

bool MerklePatriciaTrie::remove(const std::vector<uint8_t> &Key) {
  Nibbles KeyNibbles = nibbles::fromBytes(Key);
  auto OldRoot = Root;
  Root = remove(Root, KeyNibbles);
  return Root != OldRoot;
}

std::vector<uint8_t> MerklePatriciaTrie::rootHash() const {
  return hash(*Root);
}

bool MerklePatriciaTrie::empty() const { return isEmpty(*Root); }

std::shared_ptr<Node> MerklePatriciaTrie::get(std::shared_ptr<Node> NodePtr,
                                              const Nibbles &Key) const {
  if (isEmpty(*NodePtr) || Key.empty()) {
    return NodePtr;
  }

  if (getIf<LeafNode>(NodePtr)) {
    return NodePtr;
  }

  if (const auto *BranchNodePtr = getIf<BranchNode>(NodePtr)) {
    Nibble Index = Key[0];
    Nibbles RemainingKey = nibbles::subslice(Key, 1);
    return get(BranchNodePtr->Branches[Index], RemainingKey);
  }

  if (const auto *ExtensionNodePtr = getIf<ExtensionNode>(NodePtr)) {
    size_t MatchedLen =
        nibbles::commonPrefixLength(Key, ExtensionNodePtr->Path);

    if (MatchedLen == ExtensionNodePtr->Path.size()) {
      Nibbles RemainingKey = nibbles::subslice(Key, MatchedLen);
      return get(ExtensionNodePtr->Next, RemainingKey);
    }
    return EmptyNodePtr;
  }

  return EmptyNodePtr;
}

std::shared_ptr<Node>
MerklePatriciaTrie::put(std::shared_ptr<Node> NodePtr, const Nibbles &Key,
                        const std::vector<uint8_t> &Value) {
  return std::visit(
      [&](const auto &N) -> std::shared_ptr<Node> {
        using T = std::decay_t<decltype(N)>;

        if constexpr (std::is_same_v<T, EmptyNode>) {
          return std::make_shared<Node>(LeafNode(Key, Value));
        } else if constexpr (std::is_same_v<T, LeafNode>) {
          return putInLeaf(N, Key, Value);
        } else if constexpr (std::is_same_v<T, BranchNode>) {
          return putInBranch(N, Key, Value);
        } else if constexpr (std::is_same_v<T, ExtensionNode>) {
          return putInExtension(N, Key, Value);
        }
      },
      *NodePtr);
}

std::shared_ptr<Node>
MerklePatriciaTrie::putInLeaf(const LeafNode &Leaf, const Nibbles &Key,
                              const std::vector<uint8_t> &Value) {
  size_t MatchedLen = nibbles::commonPrefixLength(Key, Leaf.Path);

  if (MatchedLen == Leaf.Path.size() && MatchedLen == Key.size()) {
    return std::make_shared<Node>(LeafNode(Key, Value));
  }

  auto Branch = std::make_shared<Node>(BranchNode());
  auto *BranchPtr = std::get_if<BranchNode>(Branch.get());

  if (MatchedLen == Leaf.Path.size()) {
    BranchPtr->setValue(Leaf.Value);
    Nibbles RemainingKey = nibbles::subslice(Key, MatchedLen);
    if (!RemainingKey.empty()) {
      Nibble Index = RemainingKey[0];
      Nibbles NewKey = nibbles::subslice(RemainingKey, 1);
      BranchPtr->setBranch(Index,
                           std::make_shared<Node>(LeafNode(NewKey, Value)));
    }
  } else if (MatchedLen == Key.size()) {
    BranchPtr->setValue(Value);
    Nibbles RemainingPath = nibbles::subslice(Leaf.Path, MatchedLen);
    Nibble Index = RemainingPath[0];
    Nibbles NewPath = nibbles::subslice(RemainingPath, 1);
    BranchPtr->setBranch(Index,
                         std::make_shared<Node>(LeafNode(NewPath, Leaf.Value)));
  } else {
    Nibbles LeafRemaining = nibbles::subslice(Leaf.Path, MatchedLen);
    Nibbles KeyRemaining = nibbles::subslice(Key, MatchedLen);

    Nibble LeafIndex = LeafRemaining[0];
    Nibble KeyIndex = KeyRemaining[0];

    Nibbles NewLeafPath = nibbles::subslice(LeafRemaining, 1);
    Nibbles NewKeyPath = nibbles::subslice(KeyRemaining, 1);

    BranchPtr->setBranch(
        LeafIndex, std::make_shared<Node>(LeafNode(NewLeafPath, Leaf.Value)));
    BranchPtr->setBranch(KeyIndex,
                         std::make_shared<Node>(LeafNode(NewKeyPath, Value)));
  }

  if (MatchedLen > 0) {
    // Create extension node for common prefix
    Nibbles CommonPrefix = nibbles::subslice(Key, 0, MatchedLen);
    return std::make_shared<Node>(ExtensionNode(CommonPrefix, Branch));
  }

  return Branch;
}

std::shared_ptr<Node>
MerklePatriciaTrie::putInBranch(const BranchNode &Branch, const Nibbles &Key,
                                const std::vector<uint8_t> &Value) {
  if (Key.empty()) {
    // Set value at this branch node
    auto NewBranch = std::make_shared<Node>(Branch);
    std::get<BranchNode>(*NewBranch).setValue(Value);
    return NewBranch;
  }

  Nibble Index = Key[0];
  Nibbles RemainingKey = nibbles::subslice(Key, 1);

  auto NewBranch = std::make_shared<Node>(Branch);
  auto *NewBranchPtr = std::get_if<BranchNode>(NewBranch.get());
  auto NewChild = put(Branch.Branches[Index], RemainingKey, Value);
  NewBranchPtr->setBranch(Index, NewChild);

  return NewBranch;
}

std::shared_ptr<Node>
MerklePatriciaTrie::putInExtension(const ExtensionNode &Ext, const Nibbles &Key,
                                   const std::vector<uint8_t> &Value) {
  size_t MatchedLen = nibbles::commonPrefixLength(Key, Ext.Path);

  if (MatchedLen == Ext.Path.size()) {
    // Full match with extension path
    Nibbles RemainingKey = nibbles::subslice(Key, MatchedLen);
    auto NewNext = put(Ext.Next, RemainingKey, Value);
    return std::make_shared<Node>(ExtensionNode(Ext.Path, NewNext));
  }

  // Partial match, need to split extension
  auto Branch = std::make_shared<Node>(BranchNode());
  auto *BranchPtr = std::get_if<BranchNode>(Branch.get());

  Nibbles CommonPrefix = nibbles::subslice(Key, 0, MatchedLen);
  Nibbles ExtRemaining = nibbles::subslice(Ext.Path, MatchedLen);
  Nibbles KeyRemaining = nibbles::subslice(Key, MatchedLen);

  if (ExtRemaining.size() == 1) {
    // Extension remainder is single nibble, put next directly in branch
    Nibble ExtIndex = ExtRemaining[0];
    BranchPtr->setBranch(ExtIndex, Ext.Next);
  } else {
    // Extension remainder is multiple nibbles, create new extension
    Nibble ExtIndex = ExtRemaining[0];
    Nibbles NewExtPath = nibbles::subslice(ExtRemaining, 1);
    BranchPtr->setBranch(
        ExtIndex, std::make_shared<Node>(ExtensionNode(NewExtPath, Ext.Next)));
  }

  if (KeyRemaining.empty()) {
    // Key ends at branch
    BranchPtr->setValue(Value);
  } else {
    // Key continues past branch
    Nibble KeyIndex = KeyRemaining[0];
    Nibbles NewKeyPath = nibbles::subslice(KeyRemaining, 1);
    BranchPtr->setBranch(KeyIndex,
                         std::make_shared<Node>(LeafNode(NewKeyPath, Value)));
  }

  if (MatchedLen > 0) {
    return std::make_shared<Node>(ExtensionNode(CommonPrefix, Branch));
  }

  return Branch;
}

// Internal remove implementation
std::shared_ptr<Node> MerklePatriciaTrie::remove(std::shared_ptr<Node> NodePtr,
                                                 const Nibbles &Key) {
  if (isEmpty(*NodePtr)) {
    return NodePtr;
  }

  if (const auto *LeafNodePtr = getIf<LeafNode>(NodePtr)) {
    if (LeafNodePtr->Path == Key) {
      return EmptyNodePtr;
    }
    return NodePtr; // Key not found
  }

  if (const auto *BranchNodePtr = getIf<BranchNode>(NodePtr)) {
    if (Key.empty()) {
      // Remove value from branch node
      auto NewBranch = std::make_shared<Node>(*BranchNodePtr);
      std::get<BranchNode>(*NewBranch).removeValue();
      auto *NewBranchPtr = std::get_if<BranchNode>(NewBranch.get());

      // Check if branch can be simplified
      size_t BranchCount = NewBranchPtr->branchCount();
      if (BranchCount == 0) {
        return EmptyNodePtr;
      }
      if (BranchCount == 1 && !NewBranchPtr->Value.has_value()) {
        // Convert to extension or leaf
        auto SingleBranch = NewBranchPtr->getSingleBranch();
        if (SingleBranch.has_value()) {
          auto Child = NewBranchPtr->Branches[*SingleBranch];
          if (const auto *LeafChild = getIf<LeafNode>(Child)) {
            Nibbles NewPath = {*SingleBranch};
            NewPath.insert(NewPath.end(), LeafChild->Path.begin(),
                           LeafChild->Path.end());
            return std::make_shared<Node>(LeafNode(NewPath, LeafChild->Value));
          }
          if (const auto *ExtChild = getIf<ExtensionNode>(Child)) {
            Nibbles NewPath = {*SingleBranch};
            NewPath.insert(NewPath.end(), ExtChild->Path.begin(),
                           ExtChild->Path.end());
            return std::make_shared<Node>(
                ExtensionNode(NewPath, ExtChild->Next));
          }
        }
      }

      return NewBranch;
    }

    Nibble Index = Key[0];
    Nibbles RemainingKey = nibbles::subslice(Key, 1);

    auto NewChild = remove(BranchNodePtr->Branches[Index], RemainingKey);
    if (NewChild == BranchNodePtr->Branches[Index]) {
      return NodePtr; // Nothing changed
    }

    auto NewBranch = std::make_shared<Node>(*BranchNodePtr);
    auto *NewBranchPtr = std::get_if<BranchNode>(NewBranch.get());
    NewBranchPtr->setBranch(Index, NewChild);

    // Check if branch can be simplified after removal
    size_t BranchCount = NewBranchPtr->branchCount();
    if (BranchCount == 0 && !NewBranchPtr->Value.has_value()) {
      return EmptyNodePtr;
    }
    if (BranchCount == 1 && !NewBranchPtr->Value.has_value()) {
      auto SingleBranch = NewBranchPtr->getSingleBranch();
      if (SingleBranch.has_value()) {
        auto Child = NewBranchPtr->Branches[*SingleBranch];
        if (const auto *LeafChild = getIf<LeafNode>(Child)) {
          Nibbles NewPath = {*SingleBranch};
          NewPath.insert(NewPath.end(), LeafChild->Path.begin(),
                         LeafChild->Path.end());
          return std::make_shared<Node>(LeafNode(NewPath, LeafChild->Value));
        }
        if (const auto *ExtChild = getIf<ExtensionNode>(Child)) {
          Nibbles NewPath = {*SingleBranch};
          NewPath.insert(NewPath.end(), ExtChild->Path.begin(),
                         ExtChild->Path.end());
          return std::make_shared<Node>(ExtensionNode(NewPath, ExtChild->Next));
        }
      }
    }

    return NewBranch;
  }

  if (const auto *ExtensionNodePtr = getIf<ExtensionNode>(NodePtr)) {
    size_t MatchedLen =
        nibbles::commonPrefixLength(Key, ExtensionNodePtr->Path);

    if (MatchedLen < ExtensionNodePtr->Path.size()) {
      return NodePtr; // Key doesn't match extension path
    }

    Nibbles RemainingKey = nibbles::subslice(Key, MatchedLen);
    auto NewNext = remove(ExtensionNodePtr->Next, RemainingKey);

    if (NewNext == ExtensionNodePtr->Next) {
      return NodePtr; // Nothing changed
    }

    if (isEmpty(*NewNext)) {
      return EmptyNodePtr;
    }

    // Check if extension can be merged with child
    if (const auto *LeafNext = getIf<LeafNode>(NewNext)) {
      Nibbles NewPath = ExtensionNodePtr->Path;
      NewPath.insert(NewPath.end(), LeafNext->Path.begin(),
                     LeafNext->Path.end());
      return std::make_shared<Node>(LeafNode(NewPath, LeafNext->Value));
    }

    if (const auto *ExtNext = getIf<ExtensionNode>(NewNext)) {
      Nibbles NewPath = ExtensionNodePtr->Path;
      NewPath.insert(NewPath.end(), ExtNext->Path.begin(), ExtNext->Path.end());
      return std::make_shared<Node>(ExtensionNode(NewPath, ExtNext->Next));
    }

    return std::make_shared<Node>(
        ExtensionNode(ExtensionNodePtr->Path, NewNext));
  }

  return NodePtr;
}

} // namespace zen::evm::mpt
