pragma solidity ^0.8.20;

import {Math} from "./Math.sol";
import {Errors} from "./Errors.sol";
import {P256} from "./P256.sol";

contract testEcdsaR1Contract {
    function test_ecdsa_verify_p256() public payable returns (bool) {
        bytes32 h = 0xaf2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf;
        bytes32 r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716;
        // bytes32 s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8;
        bytes32 s = 0x0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9; // n - s
        bytes32 px = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6;
        bytes32 py = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299;

        bool isValid =  P256.verifySolidity(h, r, s, px, py);
        require(isValid, "Signature verification failed");
        return isValid;
    }
}