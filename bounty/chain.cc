
#include "util.h"

struct tr {
    u256 s, r;
    uint8_t v;
    u256 from;
    u256 to;
    u256 value;
};

struct Pending {
    u256 to;
    u256 value;
    u256 block; // block number
    Pending(u256 a, u256 b, u256 c) {
        to = a; value = b; block = c;
    }
    Pending() {
    }
    Pending(Pending const &p) {
        to = p.to;
        value = p.value;
        block = p.block;
    }
};

std::map<u256, u256> balances;
std::map<u256, bool> signers;
std::map<u256, u256> nonces;
std::map<u256, u256> block_hash;
std::map<u256, Pending> pending;
std::map<u256, u256> mainnet_result;

u256 mainnet_query = 0;
u256 prev_mainnet_query = 0;

u256 block_number;

// well there are two modes, one is for transaction files, not all commands are allowed there

void exit_error(const char*str) {
    exit(-1);
}

u256 hashFile() {
    FILE *f = openFile("state.data", "rb");
    bool eof = false;
	std::vector<u256> res;
	res.resize(2);
    int level = 1;
    int i = 0;
    while (true) {
        u256 elem = get_bytes32(f, eof);
        if (eof) break;
        if (i == res.size()) {
            level++;
            res.resize(res.size()*2);
        }
        res[i] = elem;
        i++;
    }
    fclose(f);
    
    return hashRec(res);
}

void process(FILE *f, u256 hash, bool restricted, bool &eof) {
    u256 control = get_bytes32(f);
    if (control == 0) {
        eof = true;
    }
    // Transaction: remove from account, add to pending
    if (control == 1) {
        u256 from = get_bytes32(f);
        u256 to = get_bytes32(f);
        u256 value = get_bytes32(f);
        u256 nonce = get_bytes32(f);
        u256 r = get_bytes32(f);
        u256 s = get_bytes32(f);
        u256 v = get_bytes32(f);
        u256 hash = keccak256(to, value, nonce);
        std::cout << "Processing transaction from " << from << " to " <<  to << std::endl;
        if (ecrecover(r, s, v, hash) != from) {
            std::cout << "Signature didn't match" << std::endl;
            return;
        }
        u256 bal = balances[from];
        // if has a pending transaction, ignore this one (can be resubmitted)
        if (bal < v || nonces[from] != nonce || pending.find(from) != pending.end()) return;
        balances[from] = bal - v;
        nonces[from]++;
        pending[from] = Pending(to, value, block_number);
    }
    // Confirm transaction
    else if (control == 2) {
        u256 from = get_bytes32(f);
        u256 hash = get_bytes32(f);
        u256 block = get_bytes32(f);
        std::cout << "Address " << from << " confirming block " << block << std::endl;
        u256 r = get_bytes32(f);
        u256 s = get_bytes32(f);
        u256 v = get_bytes32(f);
        if (ecrecover(r, s, v, hash) != from) {
            std::cout << "Signature didn't match" << std::endl;
            return;
        }
        Pending p = pending[from];
        if (block_hash.count(block) == 0 || block_hash[block] != hash || p.block > block) return;
        balances[p.to] += p.value;
        pending.erase(from);
    }
    // Mainnet query
    else if (control == 8) {
        mainnet_query = get_bytes32(f);
    }
    else if (control == 9) {
        prev_mainnet_query = get_bytes32(f);
    }
    if (restricted) return;
    // Block hash
    if (control == 3) {
        u256 num = get_bytes32(f);
        u256 hsh = get_bytes32(f);
        std::cout << "Parent block " << num << " hash " << hsh << std::endl;
        block_hash[num] = hsh;
        block_number = max(num+1, block_number);
        block_hash[block_number] = hash;
    }
    // Balance, nonce
    else if (control == 4) {
        u256 addr = get_bytes32(f);
        u256 v = get_bytes32(f);
        u256 nonce = get_bytes32(f);
        balances[addr] += v;
        nonces[addr] += nonce;
    }
    // Pending transaction
    else if (control == 5) {
        u256 from = get_bytes32(f);
        u256 to = get_bytes32(f);
        u256 value = get_bytes32(f);
        u256 block = get_bytes32(f);
        pending[from] = Pending(to, value, block);
    }
    // Add signer
    else if (control == 6) {
        u256 addr = get_bytes32(f);
        signers[addr] = true;
    }
    // Remove signer
    else if (control == 7) {
        u256 addr = get_bytes32(f);
        signers[addr] = false;
    }
    // Mainnet reply
    else if (control == 10) {
        u256 id = get_bytes32(f);
        u256 mainnet_reply = get_bytes32(f);
        if (id != prev_mainnet_query) exit_error("mainnet replied to wrong query");
        mainnet_result[id] = mainnet_reply;
        prev_mainnet_query = 0;
    }
    // Mainnet result
    else if (control == 11) {
        u256 id = get_bytes32(f);
        u256 reply = get_bytes32(f);
        mainnet_result[id] = reply;
    }
}

void processFile(char const *fname, u256 hash, bool restr) {
    bool eof = false;
    FILE *f = openFile(fname, "rb");
    while (!eof) {
        process(f, hash, restr, eof);
    }
    fclose(f);
}

void put_bytes32(FILE *f, u256 a) {
    std::vector<uint8_t> v = toBigEndian(a);
    fwrite(v.data(), 1, 32, f);
}

void finalize() {
    // open file for writing
    FILE *f = openFile("state.data", "wb");
    // output block hashes <-- old hashes could be removed
    for (auto const& x : block_hash) {
        put_bytes32(f, 3);
        put_bytes32(f, x.first);
        put_bytes32(f, x.second);
    }
    // output balances
    for (auto const& x : balances) {
        put_bytes32(f, 4);
        put_bytes32(f, x.first);
        put_bytes32(f, balances[x.first]);
        put_bytes32(f, nonces[x.first]);
    }
    // output pending
    for (auto const& x : pending) {
        put_bytes32(f, 5);
        put_bytes32(f, x.first);
        put_bytes32(f, x.second.to);
        put_bytes32(f, x.second.value);
        put_bytes32(f, x.second.block);
    }
    // output signers
    for (auto const& x : signers) {
        if (!x.second) continue;
        put_bytes32(f, 6);
        put_bytes32(f, x.first);
    }
    // output query
    put_bytes32(f, 9);
    // output mainnet results
    for (auto const& x : mainnet_result) {
        put_bytes32(f, 11);
        put_bytes32(f, x.first);
        put_bytes32(f, x.second);
    }
    fclose(f);
    if (mainnet_query != 0) {
        f = openFile("query.data", "wb");
        put_bytes32(f, mainnet_query);
        fclose(f);
    }
    if (prev_mainnet_query != 0) exit_error("mainnet query not replied to");
}

void outputBalances() {
    // open file for writing
    FILE *f = openFile("balances.data", "wb");
    // output balances
    for (auto const& x : balances) {
        std::cout << "Balance for " << hex(x.first) << " is " << x.second << std::endl;
        put_bytes32(f, x.first);
        put_bytes32(f, x.second);
    }
    fclose(f);
}

std::vector<uint8_t> secretToPublic(u256 secret) {
    std::vector<uint8_t> _secret = toBigEndian(secret);
	auto* ctx = getCtx();
	secp256k1_pubkey rawPubkey;
	// Creation will fail if the secret key is invalid.
	std::vector<uint8_t> serializedPubkey(65, 0);
	if (!secp256k1_ec_pubkey_create(ctx, &rawPubkey, _secret.data())) {
        std::cout << "Secret key invalid" << std::endl;
		return serializedPubkey;
    }
	size_t serializedPubkeySize = serializedPubkey.size();
	secp256k1_ec_pubkey_serialize(
			ctx, serializedPubkey.data(), &serializedPubkeySize,
			&rawPubkey, SECP256K1_EC_UNCOMPRESSED
	);
	assert(serializedPubkeySize == serializedPubkey.size());
	// Expect single byte header of value 0x04 -- uncompressed public key.
	assert(serializedPubkey[0] == 0x04);
    return serializedPubkey;
}

int main(int argc, char **argv)
{
    char opt = '0';
    if (argc > 1)
        opt = argv[1][0];
    switch (opt)
    {
    case '0':
    {
        std::cout << "Hashing file" << std::endl;
        u256 hash = hashFile();
        block_hash[0] = hash;
        std::cout << "Hash " << hash << std::endl;
        processFile("state.data", hash, false);
        processFile("control.data", hash, false);
        processFile("input.data", hash, true);
        finalize();
        outputBalances();
        break;
    }
    case 'g':
    {
        srand(time(NULL));
        std::cout << "Generating secret key (not really secure)" << std::endl;
        std::vector<uint8_t> v(32, 0);
        for (int i = 0; i < 32; i++)
        {
            v[i] = rand() & 0xff;
        }
        u256 secret = fromBigEndian(v);
        std::cout << "It is " << secret << std::endl;
        FILE *f = openFile("secret.data", "wb");
        put_bytes32(f, secret);
        fclose(f);
        std::cout << "Wrote secret to secret.data" << std::endl;
        break;
    }
    case 't':
    {
        std::cout << "Generating a transaction" << std::endl;
        FILE *f = openFile("secret.data", "rb");
        u256 secret = get_bytes32(f);
        fclose(f);

        std::cout << "Got secret key " << secret << std::endl;

        std::vector<uint8_t> pub = secretToPublic(secret);

        u256 x = fromBigEndian(pub.begin() + 1, pub.begin() + 33);
        u256 y = fromBigEndian(pub.begin() + 33, pub.end());

        u256 from = publicToAddress(pub);

        std::cout << "X: " << x << " Y: " << y << std::endl;
        std::cout << "Address: " << from << std::endl;

        u256 to = 1234567890;
        u256 value = 333444;
        u256 nonce = 0;

        u256 hash = keccak256(to, value, nonce);
        std::cout << "Message hash: " << hash << std::endl;

        Signature sig = sign(secret, hash);

        f = openFile("input.data", "wb");
        put_bytes32(f, 1);
        put_bytes32(f, from);
        put_bytes32(f, to);
        put_bytes32(f, value);
        put_bytes32(f, nonce);

        put_bytes32(f, sig.r);
        put_bytes32(f, sig.s);
        put_bytes32(f, sig.v);
        fclose(f);

        break;
    }
    case 'b':
    {
        std::cout << "Adding balance" << std::endl;
        FILE *f = openFile("secret.data", "rb");
        u256 secret = get_bytes32(f);
        fclose(f);

        std::cout << "Got secret key " << secret << std::endl;

        std::vector<uint8_t> pub = secretToPublic(secret);

        u256 x = fromBigEndian(pub.begin() + 1, pub.begin() + 33);
        u256 y = fromBigEndian(pub.begin() + 33, pub.end());

        u256 from = publicToAddress(pub);
        u256 value = 1000000;
        u256 nonce = 0;

        std::cout << "X: " << x << " Y: " << y << std::endl;
        std::cout << "Address: " << from << std::endl;

        f = openFile("control.data", "wb");
        put_bytes32(f, 4);
        put_bytes32(f, from);
        put_bytes32(f, value);
        put_bytes32(f, nonce);

        fclose(f);

        break;
    }
    case 'c':
    {
        std::cout << "Confirming block" << std::endl;
        FILE *f = openFile("secret.data", "rb");
        u256 secret = get_bytes32(f);
        fclose(f);

        std::cout << "Got secret key " << secret << std::endl;

        std::vector<uint8_t> pub = secretToPublic(secret);

        u256 x = fromBigEndian(pub.begin() + 1, pub.begin() + 33);
        u256 y = fromBigEndian(pub.begin() + 33, pub.end());

        u256 from = publicToAddress(pub);

        std::cout << "X: " << hex(x) << " Y: " << hex(y) << std::endl;
        std::cout << "Address: " << hex(from) << std::endl;

        u256 hash = hashFile();
        block_hash[0] = hash;
        std::cout << "Hash " << hash << std::endl;
        processFile("state.data", hash, false);

        std::cout << "Block number " << block_number << " with hash " << hex(block_hash[block_number]) << std::endl;
        std::cout << "Message hash: " << hash << std::endl;

        Signature sig = sign(secret, hash);

        f = openFile("input.data", "wb");
        put_bytes32(f, 2);
        put_bytes32(f, from);
        put_bytes32(f, hash);
        put_bytes32(f, block_number);

        put_bytes32(f, sig.r);
        put_bytes32(f, sig.s);
        put_bytes32(f, sig.v);
        fclose(f);

        break;
    }
    case 'h':
    {
        // std::cout << block_hash[23] << std::endl;
        std::cout << "Truebit Plasma task. Options: " << std::endl;
        std::cout << "0: perform the task" << std::endl;
        std::cout << "h: print help" << std::endl;
        break;
    }
    }
    return 0;
}
