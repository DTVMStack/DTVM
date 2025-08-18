// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_TEST_MPT_MERKLE_PATRICIA_TRIE_H
#define ZEN_TEST_MPT_MERKLE_PATRICIA_TRIE_H

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace zen::evm::mpt {

using Nibble = uint8_t;
using Nibbles = std::vector<Nibble>;

struct EmptyNode {};

struct LeafNode {
  Nibbles Path;
  std::vector<uint8_t> Value;

  LeafNode(const Nibbles &Path, const std::vector<uint8_t> &Value)
      : Path(Path), Value(Value) {}

  static LeafNode fromKeyValue(const std::vector<uint8_t> &Key,
                               const std::vector<uint8_t> &Value);
};

struct Node;

struct BranchNode {
  std::array<std::shared_ptr<Node>, 16> Branches;
  std::optional<std::vector<uint8_t>> Value;

  BranchNode();

  void setBranch(Nibble Index, std::shared_ptr<Node> NodePtr);
  void removeBranch(Nibble Index);
  void setValue(const std::vector<uint8_t> &Val);
  void removeValue();
  bool hasContent() const;
  size_t branchCount() const;
  std::optional<Nibble> getSingleBranch() const;
};

struct ExtensionNode {
  Nibbles Path;
  std::shared_ptr<Node> Next;

  ExtensionNode(const Nibbles &Path, std::shared_ptr<Node> Next)
      : Path(Path), Next(std::move(Next)) {}
};

struct Node
    : public std::variant<EmptyNode, LeafNode, BranchNode, ExtensionNode> {
  using variant::variant;
};

std::vector<uint8_t> serialize(const Node &Node);
std::vector<uint8_t> hash(const Node &Node);

inline bool isEmpty(const Node &Node) {
  return std::holds_alternative<EmptyNode>(Node);
}

// Nibbles utility functions
namespace nibbles {
// Convert byte to two nibbles
std::pair<Nibble, Nibble> fromByte(uint8_t Byte);

// Convert bytes to nibbles
Nibbles fromBytes(const std::vector<uint8_t> &Bytes);

// Convert string to nibbles
Nibbles fromString(const std::string &Str);

// Convert nibbles to prefixed bytes (for serialization)
std::vector<uint8_t> toPrefixed(const Nibbles &NibblesData, bool IsLeaf);

// Convert nibbles back to bytes (must be even length)
std::vector<uint8_t> toBytes(const Nibbles &NibblesData);

// Find common prefix length between two nibble arrays
size_t commonPrefixLength(const Nibbles &A, const Nibbles &B);

// Get subslice of nibbles
Nibbles subslice(const Nibbles &NibblesData, size_t Start,
                 size_t End = SIZE_MAX);
} // namespace nibbles

// Main Merkle Patricia Trie class
class MerklePatriciaTrie {
private:
  std::shared_ptr<Node> Root;

  // Internal recursive functions
  std::shared_ptr<Node> get(std::shared_ptr<Node> NodePtr,
                            const Nibbles &Key) const;

  std::optional<std::vector<uint8_t>> getWithPath(std::shared_ptr<Node> NodePtr,
                                                  const Nibbles &Key) const;

  std::shared_ptr<Node> put(std::shared_ptr<Node> NodePtr, const Nibbles &Key,
                            const std::vector<uint8_t> &Value);

  std::shared_ptr<Node> remove(std::shared_ptr<Node> NodePtr,
                               const Nibbles &Key);

  // Helper functions for node operations
  std::shared_ptr<Node> putInBranch(const BranchNode &Branch,
                                    const Nibbles &Key,
                                    const std::vector<uint8_t> &Value);

  std::shared_ptr<Node> putInExtension(const ExtensionNode &Ext,
                                       const Nibbles &Key,
                                       const std::vector<uint8_t> &Value);

  std::shared_ptr<Node> putInLeaf(const LeafNode &Leaf, const Nibbles &Key,
                                  const std::vector<uint8_t> &Value);

public:
  MerklePatriciaTrie();

  std::optional<std::vector<uint8_t>>
  get(const std::vector<uint8_t> &Key) const;
  void put(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &Value);
  bool remove(const std::vector<uint8_t> &Key);

  std::vector<uint8_t> rootHash() const;

  bool empty() const;

  std::shared_ptr<Node> getRoot() const { return Root; }
};

} // namespace zen::evm::mpt

#endif // ZEN_TEST_MPT_MERKLE_PATRICIA_TRIE_H
