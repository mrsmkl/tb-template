
pragma solidity ^0.5.0;

contract App {

    function isOperator(address a) public returns (bool);

    // mappings from block numbers to header or state files
    mapping (uint => bytes32) headers;
    mapping (uint => bytes32) states;

    uint last_header; // last accepted header

    uint constant TIMEOUT = 10;

    struct Proposition {
        uint number;
        uint bn;
        address owner;
        bytes32 data;
    }

    mapping (bytes32 => Proposition) propositions;

    event Proposed(address s, uint number, bytes32 header);

    function bondDeposit(address a, uint amount) private;
    function unbondDeposit(address a, uint amount) private;

    function proposeHeader(uint number, bytes32 header, bytes32 data) public {
        require(isOperator(msg.sender), "only operator can add headers");
        require(number > last_header, "state already deprecated");
        bondDeposit(msg.sender, 1 ether);
        propositions[header] = Proposition(number, block.number, msg.sender, data);
        emit Proposed(msg.sender, number, header);
    }

    function finalizeHeader(bytes32 header) public {
        Proposition storage p = propositions[header];
        require(p.bn + TIMEOUT < block.number, "wait for timeout");
        unbondDeposit(p.owner, 1 ether);
        if (last_header >= p.number) return;
        last_header = p.number;
        headers[last_header] = header;
    }

    uint uniq;

    struct Challenge {
        bytes32 header;
        address prover;
        address other;
        uint agree;
        uint disagree;
        uint bn;
        uint step;
        bytes32 data;
    }

    mapping (bytes32 => Challenge) challenges;

    function challengeHeader(bytes32 header) public {
        Proposition storage p = propositions[header];
        bytes32 id = keccak256(abi.encodePacked(header, uniq));
        uniq++;
        bondDeposit(msg.sender, 1 ether);
        challenges[id] = Challenge(header, p.owner, msg.sender, last_header, p.number, block.number, 0, p.data);
        delete propositions[header];
    }

    function post(bytes32 id, bytes32 header, bytes32 data) public {
        Challenge storage c = challenges[id];
        require(int(c.disagree) - int(c.agree) > 1, "already found the disagreement");
        require(c.step % 2 == 0, "prover's turn");
        require(msg.sender == c.prover, "only prover can answer");
        // post middle state
        c.header = header;
        c.data = data;
        c.step++;
        c.bn = block.number;
    }

    function query(bytes32 id, bool lower) public {
        Challenge storage c = challenges[id];
        require(int(c.disagree) - int(c.agree) > 1, "already found the disagreement");
        require(c.step % 2 == 1, "verifiers's turn");
        require(msg.sender == c.other, "only verifier can answer");
        // posted middle state
        if (lower) {
            c.disagree = (c.disagree+c.agree)/2;
        }
        else {
            c.agree = (c.disagree+c.agree)/2;
        }
        c.step++;
        c.bn = block.number;
    }

    // resolve whether the header is correct, data availability should be guaranteed now
    function resolve(bytes32 id) public {
        Challenge storage c = challenges[id];
        require(c.disagree == c.agree + 1, "already found the disagreement");
        require(c.step % 2 == 1, "verifiers's turn");
        require(msg.sender == c.other, "only verifier can answer");
        require(invalidHeader(c.header, c.data), "header has not been found invalid");
        unbondDeposit(c.other, 2 ether);
        delete challenges[id];
    }

    function timeoutChallenge(bytes32 id) public {
        Challenge storage c = challenges[id];
        require(c.bn < block.number + TIMEOUT, "timeout not elapsed");
        require(headerTimeout(c.header, c.data) < block.number, "waiting to compute header");
        // address loser = c.step%2 == 0 ? c.prover : c.other;
        address winner = c.step%2 == 1 ? c.prover : c.other;
        unbondDeposit(winner, 2 ether);
        delete challenges[id];
    }

    function invalidHeader(bytes32 header, bytes32 data) public returns (bool);
    function headerTimeout(bytes32 header, bytes32 data) public returns (uint);

}


