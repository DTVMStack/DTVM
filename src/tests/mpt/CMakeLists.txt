set(MPT_SRCS merkle_patricia_trie.cpp rlp_encoding.cpp)

add_library(mpt OBJECT ${MPT_SRCS})
