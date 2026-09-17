pragma solidity ^0.8.0;

contract FibonacciTest {
    
    function fibonacci(uint n) public pure returns (uint) {
        if (n == 0) return 0;
        if (n == 1) return 1;

        uint a = 0;
        uint b = 1;
        uint result;

        for (uint i = 2; i <= n; i++) {
            result = a + b;
            a = b;
            b = result;
        }

        return result;
    }

    function fibonacciTailOptimized(uint n) public pure returns (uint) {
        if (n == 0) return 0;
        
        uint a = 0;
        uint b = 1;

        while (n > 1) {
            uint temp = b;
            b = a + b;
            a = temp;
            n--;
        }

        return b;
    }
}