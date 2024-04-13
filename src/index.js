const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// const secp256k1 = require('secp256k1');


let MAX_BLOCK_SIZE = 1000000n; // Maximum block size in bytes
let INT_MAX = 2147483647n; // Maximum integer value

const WITNESS_RESERVED_VALUE = Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex',
)
    
// function isValidSignature(signature, publicKey, message) {
//     signature = signature.slice(0, -2);
//     const signatureBuffer = Buffer.from(signature, 'hex');
//     const publicKeyBuffer = Buffer.from(publicKey, 'hex');
//     const messageBuffer = crypto.randomBytes(32);

//     return secp256k1.ecdsaVerify(signatureBuffer, messageBuffer, publicKeyBuffer);
// }

function isValidInput(input) {
    const requiredProperties = ['txid', 'vout', 'prevout', 'sequence'];
    for (const prop of requiredProperties) {
        if (!input.hasOwnProperty(prop)) {
            return false;
        }
    }
    return true
}

// Function to calculate transaction size
function calculateTransactionSize(tx) {
    // Initialize size counter
    let size = 0;

    // Fixed-size fields
    size += getVarIntSize(tx.version); // Size of the version (varint)
    size += getVarIntSize(tx.locktime); // Size of the locktime (varint)
    size += 4; // Size of marker and flag (always 4 bytes)

    // Input data
    for (const input of tx.vin) {
        size += 32; // Size of txid (32 bytes)
        size += 4; // Size of vout (4 bytes)
        size += 4; // Size of sequence (4 bytes)
    }

    // Output data
    for (const output of tx.vout) {
        size += 8; // Size of value (8 bytes)
        size += getVarIntSize(output.scriptpubkey.length); // Size of the scriptPubKey length (varint)
        size += output.scriptpubkey.length; // Size of the scriptPubKey data
    }

    // Witness data (if present)
    if (tx.witness) {
        size += getVarIntSize(tx.witness.length); // Size of the number of witness elements (varint)
        for (const witness of tx.witness) {
            size += getVarIntSize(witness.length); // Size of each witness element length (varint)
            size += witness.length; // Size of witness element data
        }
    }

    if (tx.vin.scriptsig !== "") {
        size += getVarIntSize(tx.vin.scriptsig?.length); // Size of the scriptSig length (varint)
        size += tx.vin.scriptsig?.length; // Size of the scriptSig data
    }

    return size;
}

// Helper function to calculate variable integer (varint) size
function getVarIntSize(num) {
    if (num < 0xfd) {
        return 1;
    } else if (num <= 0xffff) {
        return 3;
    } else if (num <= 0xffffffff) {
        return 5;
    } else {
        return 9; // Assuming no transactions larger than 2^32 - 1 exist
    }
}

// to check if the scriptPubkey is in standard format
function isStandardScriptPubkey(scriptPubkey) {
    // Check if the scriptPubkey is in Pay-to-Public-Key-Hash (P2PKH) format
    if (scriptPubkey.startsWith("76a914") && scriptPubkey.length === 50) {
        return true;
    }
    // Check if the scriptPubkey is in Pay-to-Script-Hash (P2SH) format
    if (scriptPubkey.startsWith("a914") && scriptPubkey.length === 46) {
        return true;
    }
    // Check if the scriptPubkey is in Pay-to-Witness-Public-Key-Hash (P2WPKH) format
    if (scriptPubkey.startsWith("0014") && scriptPubkey.length === 42) {
        return true;
    }
    // Check if the scriptPubkey is in Pay-to-Witness-Script-Hash (P2WSH) format
    if (scriptPubkey.startsWith("0020") && scriptPubkey.length === 42) {
        return true;
    }
    // Check if the scriptPubkey is in Pay-to-Taproot (P2TR) format
    if (scriptPubkey.startsWith("51") && scriptPubkey.length === 68) {
        return true;
    }
    // If the scriptPubkey doesn't match any known standard format, return false
    return false;
}

function hasDuplicateInputs(tx) {
    const seenOutpoints = new Set();
    for (const input of tx.vin) {
        const outpoint = { txid: input.txid, vout: input.vout };
        if (seenOutpoints.has(outpoint)) {
            return true; // Duplicate input found!
        }
        seenOutpoints.add(outpoint);
    }
    return false; // No duplicate inputs found
}

function validateTransaction(tx) {

    if (typeof tx.version !== 'number') {
        return false;
    }

    if (typeof tx.locktime !== 'number') {
        return false;
    }

    if (tx.locktime >= 500000000) {
        console.log(tx.locktime)
        console.log(tx)
        throw new Error('Locktime is not in height format')
    }

    const currentTimestamp = Math.floor(Date.now() / 1000);
    if (tx.locktime > currentTimestamp) {
        return false; // Locktime is set to a future timestamp
    }

    for (const output of tx.vout) {
        if (typeof output.value !== 'number' || !output.scriptpubkey || !isStandardScriptPubkey(output.scriptpubkey)) {
            return false;
        }
    }

    if (hasDuplicateInputs(tx)) {
        return false;
    }

    for (const input of tx.vin) {
        if (typeof input.sequence !== 'number') {
            return false;
        }
        if (input.scriptsig.length === 0 && input.witness[0].length === 0) {
            return false;
        }
    }

    for (const input of tx.vin) {
        if (!isValidInput(input)) {
            return false;
        }
    //     if (input.scriptsig.length === 0) {
    //         if (!isValidSignature(input.witness[0], input.prevout.scriptpubkey, input.prevout.scriptpubkey_asm)) {
    //             return false;
    //         }
    //     }
    //     else if (!isValidSignature(input.scriptsig, input.prevout.scriptpubkey, input.prevout.scriptpubkey_asm)) {
    //         return false;
    //     }
    }

    const BLOCK_SIZE = calculateTransactionSize(tx)
    if (BLOCK_SIZE > MAX_BLOCK_SIZE) {
        return false
    }

    if (BLOCK_SIZE < 100) {
        return false
    }

    // check if the input fees is always greater than the output fees
    for (let i = 0; i < tx.length; i++) {
        let inputFees = 0;
        let outputFees = 0;
        for (let j = 0; j < tx[i].vin.length; j++) {
            inputFees += tx[i].vin[j].value;
            // check for valid locktime
            if (tx[i].vin[j].sequence >= INT_MAX) {
                return false;
            }
        }
        for (let j = 0; j < tx[i].vout.length; j++) {
            outputFees += tx[i].vout[j].value;
        }
        if (inputFees < outputFees) {
            return false;
        }
    }
    return true
}

// Function to calculate the merkle root
function calculateMerkleRoot(coinbaseTxid, txids) {
    let hashes = [Buffer.from(coinbaseTxid, 'hex')];
    for (const txid of txids) {
        hashes.push(Buffer.from(txid, 'hex'));
    }
    while (hashes.length > 1) {
        if (hashes.length % 2 !== 0) {
            hashes.push(hashes[hashes.length - 1]); // Duplicate the last hash if odd number of hashes
        }
        const newHashes = [];
        for (let i = 0; i < hashes.length; i += 2) {
            const combinedHash = crypto.createHash('sha256').update(Buffer.concat([hashes[i], hashes[i + 1]])).digest();
            newHashes.push(combinedHash);
        }
        hashes = newHashes;
    }
    return hashes[0].toString('hex');
}

// Function to generate the block header
function generateBlockHeader(version, prevBlockHash, merkleRoot, timestamp, difficultyTarget, nonce) {
    const header = Buffer.concat([
        Buffer.alloc(4, version, 'little'), // encoded in little endian format
        Buffer.from(prevBlockHash, 'hex').reverse(), // encoded in hexadecimal code in reverse order
        Buffer.from(merkleRoot, 'hex').reverse(),
        Buffer.alloc(4, timestamp, 'little'),
        Buffer.from(difficultyTarget, 'hex').reverse(),
        Buffer.alloc(4, nonce, 'little'),
    ]);
    return header.toString('hex');
}

// const calculateWitnessCommitment = (wtxids) => {
//     const witnessRoot = generateMerkleRoot(wtxids)
//     const witnessReservedValue = WITNESS_RESERVED_VALUE.toString('hex')
//     return hash256(witnessRoot + witnessReservedValue)
// }

// Function to process each JSON file and generate block header
function processTransaction(jsonFile) {
    const transactionData = JSON.parse(fs.readFileSync(jsonFile));
    // Extract necessary data from the transaction
    if (validateTransaction(transactionData)) {
        const coinbaseTxid = transactionData.vin[0].txid;
        const txids = transactionData.vin.slice(1).map(vin => vin.txid); // Exclude coinbase transaction
        const merkleRoot = calculateMerkleRoot(coinbaseTxid, txids);

        // Block header parameters (replace with actual values)
        const version = transactionData.version;
        const prevBlockHash = "0000000000000000000000000000000000000000000000000000000000000000"; // Assuming this is the genesis block
        const timestamp = Math.floor(Date.now() / 1000);
        const difficultyTarget = '0000ffff00000000000000000000000000000000000000000000000000000000';
        const nonce = 0;

        // Generate block header
        const blockHeader = generateBlockHeader(version, prevBlockHash, merkleRoot, timestamp, difficultyTarget, nonce);
        return blockHeader;
    }
}

// Main function to traverse through files in the mempool folder
function processMempool() {
    const mempoolFolder = "mempool"; // Path to mempool folder
    const outputFile = "output.txt"; // Output file to save block headers if needed

    let blockHeaders = [];

    fs.readdirSync(mempoolFolder).forEach(filename => {
        const jsonFile = path.join(mempoolFolder, filename);
        const blockHeader = processTransaction(jsonFile);
        blockHeaders.push(blockHeader);
    });

    fs.writeFileSync(outputFile, blockHeaders.join('\n'));
    console.log("Block headers generated and saved to output.txt");
}

// Call the main function to process mempool transactions
processMempool();