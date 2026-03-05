// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OnChainMetadataNFT {
    mapping(uint256 => address) public owners;
    mapping(uint256 => string) public tokenNames;
    mapping(uint256 => string) public tokenDescriptions;

    function mint(address to, uint256 tokenId, string memory name, string memory desc) public {
        owners[tokenId] = to;
        tokenNames[tokenId] = name;
        tokenDescriptions[tokenId] = desc;
    }

    function tokenURI(uint256 tokenId) public view returns (string memory) {
        require(owners[tokenId] != address(0), "Token does not exist");
        string memory name = tokenNames[tokenId];
        string memory desc = tokenDescriptions[tokenId];
        
        // Simulating JSON metadata construction
        string memory json = string(abi.encodePacked(
            '{"name": "', name, '", "description": "', desc, '"}'
        ));

        return string(abi.encodePacked("data:application/json;base64,", _encodeBase64(bytes(json))));
    }

    function _encodeBase64(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) return "";

        string memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint256 encodedLen = 4 * ((data.length + 2) / 3);
        string memory result = new string(encodedLen);

        // OpenZeppelin Base64.sol style - see contracts/utils/Base64.sol
        assembly {
            let tablePtr := add(table, 1)
            let resultPtr := add(result, 0x20)
            let dataPtr := data
            let endPtr := add(data, mload(data))
            let afterPtr := add(endPtr, 0x20)
            let afterCache := mload(afterPtr)
            mstore(afterPtr, 0x00)

            for {} lt(dataPtr, endPtr) {} {
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(6, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(input, 0x3F))))
                resultPtr := add(resultPtr, 1)
            }

            mstore(afterPtr, afterCache)

            switch mod(mload(data), 3)
            case 1 {
                mstore8(sub(resultPtr, 1), 0x3d)
                mstore8(sub(resultPtr, 2), 0x3d)
            }
            case 2 {
                mstore8(sub(resultPtr, 1), 0x3d)
            }
            mstore(result, encodedLen)
        }

        return result;
    }
}
