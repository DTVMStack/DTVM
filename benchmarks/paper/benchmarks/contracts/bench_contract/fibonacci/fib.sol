pragma solidity ^0.8.0;

contract FibonacciTest {

    function fibonacci(uint n) public pure returns (uint) {
        if (n == 0) return 0;
        if (n == 1) return 1;
        return fibonacci(n - 1) + fibonacci(n - 2);
    }

    function fibonacciTailOptimized(uint n) public pure returns (uint) {
        return fibonacciTailRecursive(n, 0, 1);
    }

    function fibonacciTailRecursive(uint n, uint a, uint b) internal pure returns (uint) {
        if (n == 0) return a;
        if (n == 1) return b;
        return fibonacciTailRecursive(n - 1, b, a + b);
    }
}