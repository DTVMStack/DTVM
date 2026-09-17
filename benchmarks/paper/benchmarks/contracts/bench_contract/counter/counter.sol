pragma solidity ^0.8.0;
 
contract counter{
 
    uint public count;
 
    function increase() public {
        count++;
    }
     
    function decrease() public{
        count--;
    }
}