pragma solidity ^0.5.0;

contract Step {
    function getBlockData(uint num) internal returns (bytes32);
    function getState(uint num) internal returns (bytes32);

    function startTask(bytes32 prev, bytes32 tr_data, bytes32 query) internal;
    function startQueryTask(bytes32 prev) internal;
    function queryResult(bytes32 prev) internal returns (bytes memory);

    function query(bytes memory info) internal returns (bytes32);

    // compute a step in chain
    // first need to get associated query from previous block
    function initTask(uint num) public {
        startQueryTask(getState(num-1));
    }

    function startTask(uint num) public {
        bytes32 prev = getState(num-1);
        startTask(prev, getBlockData(num), query(queryResult(prev)));
    }

    // to implement a timeout, generate an id, then read a block
    // if read fails, block won't be accepted
    // so either it is too early, or there was a prevention of timeout posted on-chain

}


