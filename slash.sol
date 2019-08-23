pragma solidity ^0.5.0;

interface IToken {
    function transferFrom(address a, address b, uint v) external;
}

// additional features for the filesystem
// 1. store data in an event
// 2. modify data using merkle tree (also merkle proofs are stored in events)

contract Slash {

    IToken token;
    uint constant DEPOSIT = 1 ether;
    uint constant TIMEOUT = 1000;

    struct Deposit {
        uint balance;
        uint initial; // initial block
        uint final_block; // final block
        uint timeout;
    }

    mapping (address => Deposit) deposits;

    function add(address a, uint init) internal {
        token.transferFrom(a, address(this), DEPOSIT);
        deposits[a] = Deposit(DEPOSIT, init, 0, 0);
    }

    function remove(address a, uint fin) internal {
        deposits[a].timeout = block.number;
        deposits[a].final_block = fin;
    }

    // just slash everyone in the list
    function process(bytes32[] memory arr) internal {
        for (uint i = 0; i < arr.length; i++) {
            deposits[address(bytes20(arr[i]))].balance = 0;
        }
    }

}


