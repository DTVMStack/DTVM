# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
# pip install pycryptodome
from Crypto.Hash import keccak

def calculate_selector(signature):
    """Calculate Ethereum function selector from function signature."""
    k = keccak.new(digest_bits=256)
    k.update(signature.encode())
    return k.hexdigest()[:8]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 function_selector.py 'functionName(type1,type2,...)'")
        print("Example: python3 function_selector.py 'add(uint256,uint256)'")
        sys.exit(1)

    signature = sys.argv[1]
    selector = calculate_selector(signature)
    print(f"Function: {signature}")
    print(f"Selector: {selector}")
