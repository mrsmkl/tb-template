pragma solidity ^0.5.0;

contract Exit {
    // how to prevent posting irrelevant transactions?

    uint constant TIMEOUT = 1000;
    uint constant DEPOSIT = 1 ether;

    enum TRTYPE {
        AUTO, EXITING, OTHER, EXTRACT
    }

    struct ExitInfo {
        uint bn;
        // there are actually few transaction types
        mapping (uint => bytes[]) tr;
        uint progress;
        uint max_priority;
        uint timeout;
        mapping (address => uint) deposit;
    }

    // current earliest block to exit from
    uint current_block;
    uint current_timeout;

    uint final_block;

    mapping (address => ExitInfo) exited;

    // exit from block bn
    function startExit(uint bn) public {
        require(final_block < bn, "Block has already timeout, cannot exit anymore");
        if (bn < current_block) {
            current_block = bn;
            current_timeout = block.number + TIMEOUT;
        }
        exited[msg.sender].bn = bn;
        exited[msg.sender].timeout = block.number + TIMEOUT;
    }

    function postTransaction(address a, bytes memory tr, uint priority) public payable {
        if (a != msg.sender) {
            exited[a].deposit[msg.sender] += msg.value;
            require(exited[a].deposit[msg.sender] >= DEPOSIT, "Must post a deposit");
        }
        exited[a].tr[priority].push(tr);
        if (exited[a].max_priority < priority) exited[a].max_priority = priority;
    }

    function timeout() public {
        require(current_timeout < block.number, "Wait for timeout");
        final_block = current_block;
        current_block = 1 ether;
    }

    function clearQueue(address a) internal returns (bool);
    function queueTransaction(address a, uint priority, bytes memory tr) internal returns (bool);

    // extract instruction is passed to extract delegate
    function finalizedTransaction(bytes memory extract) public;

    // run transactions with different priorities
    function runTr(address a) public {
        ExitInfo storage e = exited[a];
        require(clearQueue(a), "Clear the last transaction first");
        require(e.progress <= e.max_priority, "All transactions already progressed");
        if (e.tr[e.progress].length == 0) {
            e.progress++;
            return;
        }
        bytes storage tr = e.tr[e.progress][e.tr[e.progress].length-1];
        e.tr[e.progress].length--;
        queueTransaction(a, e.progress, tr);
    }

}

