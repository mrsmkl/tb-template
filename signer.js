
const fs = require("fs")
const ecdsa = require('secp256k1')
const sr = require('secure-random')

let argv = require('minimist')(process.argv.slice(2))

let config = JSON.parse(fs.readFileSync("config.json"))
// let signers = JSON.parse(fs.readFileSync("signers.json"))

function main() {
    if (argv["new-key"]) {
        let privateKey = sr.randomBuffer(32)

        let pubKey = ecdsa.publicKeyCreate(privateKey, true)
        console.error("storing new key", pubKey.toString("hex"), privateKey.length)
        config.private = privateKey.toString("hex")
    }
    else if (argv["add-signer"]) {
        config.signers.push(argv["add-signer"])
    }
    else if (argv["clear"]) {
        config.signers = []
        config.blocks = {}
        config.number = 0
        if (config.private) {
            let privateKey = Buffer.from(config.private, "hex")
            let pubKey = ecdsa.publicKeyCreate(privateKey, true)
            config.signers.push(pubKey.toString("hex"))
        }
    }
    else if (argv["clear-sigs"]) {
        let header = JSON.parse(fs.readFileSync(argv["sign"]))
        header.sigs = []
        fs.writeFileSync(argv["clear-sigs"], JSON.stringify(header))
    }
    else if (argv["sign"]) {
        let privateKey = Buffer.from(config.private, "hex")
        let pubKey = ecdsa.publicKeyCreate(privateKey, true)
        console.log("using key", pubKey.toString("hex"))
        let header = JSON.parse(fs.readFileSync(argv["sign"]))
        config.blocks = config.blocks || {}
        config.number = config.number || 0
        if (config.number != header.number) {
            console.error("block number is wrong")
            return
        }
        let block = config.blocks[header.number] || {}
        config.blocks[header.number] = block
        if (block.active) {
            console.error("already have an active block", block.active)
            return
        }
        block.rejected = block.rejected || []
        block.accepted = block.accepted || []
        let data = header.data.substr(10)
        if (block.rejected.some(a => a == data)) {
            console.error("block has been rejected, will never sign it")
            return
        }
        if (block.accepted.some(a => a == data)) {
            console.error("Warning: already signed")
        }

        if (parseInt(header.data.substr(0,10)) != config.number) {
            console.error("data incompatible with block number")
            return
        }

        let buf = Buffer.from(header.data)
        console.log("signing", buf.toString())
        let sig = ecdsa.sign(buf, privateKey)
        let obj = {sig:sig.signature.toString("hex"), recovery:sig.recovery, data:buf.toString(), number:header.number}
        console.log(JSON.stringify(obj))

        header.sigs = header.sigs || []
        header.sigs.push(obj)

        block.active = data
        block.accepted.push(data)
        fs.writeFileSync(argv["sign"], JSON.stringify(header))
    }
    else if (argv["reject"]) {
        let privateKey = Buffer.from(config.private, "hex")
        let pubKey = ecdsa.publicKeyCreate(privateKey, true)
        console.log("using key", pubKey.toString("hex"))
        let header = JSON.parse(fs.readFileSync(argv["reject"]))
        config.blocks = config.blocks || {}
        config.number = config.number || 0
        if (config.number != header.number) {
            console.error("block number is wrong")
            return
        }
        let block = config.blocks[header.number] || {}
        config.blocks[header.number] = block
        block.rejected = block.rejected || []
        block.accepted = block.accepted || []
        let data = header.data.substr(10)
        if (block.accepted.some(a => a == data)) {
            console.error("block has been accepted, will never reject it")
            return
        }
        if (block.rejected.some(a => a == data)) {
            console.error("Warning: already signed")
        }

        if (parseInt(header.data.substr(0,10)) != config.number) {
            console.error("data incompatible with block number")
            return
        }

        let buf = Buffer.from(header.data)
        buf[0] = 'r'.charCodeAt(0)
        console.log("signing rejection of", buf.toString())
        let sig = ecdsa.sign(buf, privateKey)
        console.log(JSON.stringify({sig:sig.signature.toString("hex"), recovery:sig.recovery, data:buf.toString(), number:header.number}))
        block.rejected.push(data)
    }
    else if (argv["deactivate"]) {
        let header = JSON.parse(fs.readFileSync(argv["deactivate"]))
        config.blocks = config.blocks || {}
        config.number = config.number || 0
        config.messages = config.messages || []
        if (config.number != header.number) {
            console.error("block number is wrong")
            return
        }
        let block = config.blocks[header.number] || {}
        config.blocks[header.number] = block
        config.messages.push(header)
        if (header.data[0] != 'r') {
            console.log("not a rejection message")
            return
        }
        let data = header.data.substr(10)
        if (block.active != data) {
            console.error("no active block, recording message")
        }
        else {
            // recover pubkey
            let pubkey = ecdsa.recover(Buffer.from(header.data), Buffer.from(header.sig, "hex"), header.recovery, true).toString("hex")
            console.log("pubkey", pubkey, "withdrawing message")
            block.active = null
        }
    }
    // move on to the next block
    else if (argv["next"]) {
        let header = JSON.parse(fs.readFileSync(argv["next"]))
        config.number = config.number || 0
        // check all signatures
        function getsig(msg) {
            return ecdsa.recover(Buffer.from(header.data), Buffer.from(msg.sig, "hex"), msg.recovery, true).toString("hex")
        }
        if (JSON.stringify(config.signers.sort()) == JSON.stringify(header.sigs.map(getsig).sort())) {
            console.log("block accepted")
            config.messages.push(header)
            config.number++
        }
    }
    fs.writeFileSync("config.json", JSON.stringify(config))
}

main()

