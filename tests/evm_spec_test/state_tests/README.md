# EVM State Tests

This directory contains Ethereum Virtual Machine (EVM) state tests based on the [ethereum/execution-spec-tests](https://github.com/ethereum/execution-spec-tests) framework.

## Test Format

State tests follow the JSON format defined by the Ethereum execution specification. Each test case includes:

- **Environment (`env`)**: Blockchain state parameters (coinbase, gas limit, block number, etc.)
- **Pre-state (`pre`)**: Initial account states before transaction execution
- **Transaction (`transaction`)**: Transaction parameters to be executed
- **Post-state (`post`)**: Expected account states after transaction execution
- **Configuration (`config`)**: Network and fork-specific configuration
- **Metadata (`_info`)**: Test information including descriptions and references

## JSON Structure Details

### Environment (`env`)

The environment section defines the blockchain state parameters:

```json
"env": {
  "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
  "currentGasLimit": "0x044aa200",
  "currentNumber": "0x01",
  "currentTimestamp": "0x03e8",
  "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "currentDifficulty": "0x00",
  "currentBaseFee": "0x07",
  "currentExcessBlobGas": "0x00"
}
````

**Fields:**

* `currentCoinbase`: Address of the block miner/coinbase
* `currentGasLimit`: Maximum gas allowed for the block
* `currentNumber`: Current block number
* `currentTimestamp`: Block timestamp
* `currentRandom`: Random value / **prevRandao** (post-Merge)
* `currentDifficulty`: Block difficulty (0 post-Merge)
* `currentBaseFee`: Base fee per gas (EIP-1559)
* `currentExcessBlobGas`: Excess blob gas (EIP-4844)

### Pre-state (`pre`)

Defines the initial state of accounts before execution:

```json
"pre": {
  "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
    "nonce": "0x00",
    "balance": "0x3635c9adc5dea00000",
    "code": "0x",
    "storage": {}
  },
  "0x0000000000000000000000000000000000001000": {
    "nonce": "0x01",
    "balance": "0x00",
    "code": "0x6004565f5b60015f5500",
    "storage": {}
  }
}
```

**Account Fields:**

* `nonce`: Transaction count
* `balance`: Balance in wei
* `code`: Contract bytecode (empty for EOA)
* `storage`: Key-value pairs (hex strings)

### Transaction (`transaction`)

Defines the transaction(s) to be executed. Some fields are arrays to allow multiple combinations controlled by `post.indexes`.

```json
"transaction": {
  "nonce": "0x00",
  "gasPrice": "0x0a",
  "gasLimit": ["0x0186a0"],
  "to": "",
  "value": ["0x00"],
  "data": ["0x"],
  "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
  "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
}
```

**Fields:**

* `nonce`: Transaction nonce
* `gasPrice`: Gas price in wei (legacy)
* `gasLimit`: Array of gas limits
* `to`: Recipient address (**empty string `""` for contract creation**)
* `value`: Array of values to transfer
* `data`: Array of calldata payloads
* `sender`: Sender address
* `secretKey`: Private key for signing

**Optional (by tx type / fork):**

* `maxFeePerGas`, `maxPriorityFeePerGas` (EIP-1559)
* `maxFeePerBlobGas`, `blobVersionedHashes` (EIP-4844)

### Post-state (`post`)

Defines the expected result after execution for each fork:

```json
"post": {
  "Cancun": [
    {
      "hash": "0xcd2bf3206a46862ff5e58c24139f5b67ee5e6ed684ea63984ca2a3f87f948d07",
      "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
      "txbytes": "0xf860800a830186a0940000000000000000000000000000000000001000808025a09069fab60fe5c8a970860130c49d2295646da4fff858330a1fd5d260cd01e562a07a31960780931801bb34d06f89f19a529357f833c6cfda63135440a743949717",
      "indexes": { "data": 0, "gas": 0, "value": 0 },
      "state": {
        "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
          "nonce": "0x01",
          "balance": "0x3635c9adc5de996bbe",
          "code": "0x",
          "storage": {}
        },
        "0x0000000000000000000000000000000000001000": {
          "nonce": "0x01",
          "balance": "0x00",
          "code": "0x6004565f5b60015f5500",
          "storage": { "0x00": "0x01" }
        }
      }
    }
  ]
}
```

**Post-state Fields:**

* `hash`: Transaction hash
* `logs`: **Hash of transaction logs** (Keccak-256 of the logs list)
* `txbytes`: RLP-encoded signed transaction bytes
* `indexes`: Which entries from `data`/`gasLimit`/`value` arrays are used
* `state`: Final account states

### Configuration (`config`)

Network/fork configuration:

```json
"config": {
  "blobSchedule": {
    "Cancun": {
      "target": "0x03",
      "max": "0x06",
      "baseFeeUpdateFraction": "0x32f0ed"
    }
  },
  "chainid": "0x01"
}
```

### Metadata (`_info`)

Test information and references:

```json
"_info": {
  "hash": "0x5175cc36f2762b5d18be9aad27e0fb3dae1f251510f92ac64f4e6503e1139e81",
  "comment": "`execution-spec-tests` generated test",
  "filling-transition-tool": "ethereum-spec-evm-resolver 0.0.5",
  "description": "Tests PUSH0 within various deployed contracts.",
  "url": "https://github.com/ethereum/execution-spec-tests/tree/v4.5.0/tests/shanghai/eip3855_push0/test_push0.py#L32",
  "fixture-format": "state_test",
  "reference-spec": "https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3855.md",
  "reference-spec-version": "6f85bd73336de4aacfad7ac3bb3a7e1ba2d68f51",
  "eels-resolution": {
    "git-url": "https://github.com/ethereum/execution-specs.git",
    "branch": "master",
    "commit": "fa847a0e48309debee8edc510ceddb2fd5db2f2e"
  }
}
```

> `_info.hash` can be used to detect fixture changes.

## References

* [Ethereum Execution Specification](https://github.com/ethereum/execution-specs)
* [execution-spec-tests Documentation](https://eest.ethereum.org/)
* [State Test Format](https://eest.ethereum.org/main/running_tests/test_formats/state_test/)
* [Ethereum Improvement Proposals (EIPs)](https://github.com/ethereum/EIPs)

## License

This directory contains tests generated with or based on `execution-spec-tests`.
The upstream `execution-spec-tests` project is released under the MIT License.
For this repository’s license, see the local [LICENSE](LICENSE) file.

