import hashlib
import json
import struct

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def serialize_block_header(version, prev_block_hash, merkle_root, time, nBits, nonce):
    return (
        struct.pack('<L', version) +
        bytes.fromhex(prev_block_hash)[::-1] +  # Reverse byte order for little-endian
        bytes.fromhex(merkle_root)[::-1] +  # Reverse byte order for little-endian
        struct.pack('<L', time) +
        struct.pack('<L', nBits) +
        struct.pack('<L', nonce)
    )

def calculate_merkle_root(transactions):
    txids = [hash_sha256(json.dumps(tx)) for tx in transactions]
    while len(txids) > 1:
        if len(txids) % 2 != 0:
            txids.append(txids[-1])  # Duplicate the last item if the list length is odd
        txids = [hash_sha256(txids[i] + txids[i+1]) for i in range(0, len(txids), 2)]
    return txids[0]

def main():
    transaction_json = {
        "version": 1,
        "locktime": 0,
        "vin": [
            {
                "txid": "3b7dc918e5671037effad7848727da3d3bf302b05f5ded9bec89449460473bbb",
                "vout": 16,
                "prevout": {
                    "scriptpubkey": "0014f8d9f2203c6f0773983392a487d45c0c818f9573",
                    "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 f8d9f2203c6f0773983392a487d45c0c818f9573",
                    "scriptpubkey_type": "v0_p2wpkh",
                    "scriptpubkey_address": "bc1qlrvlygpudurh8xpnj2jg04zupjqcl9tnk5np40",
                    "value": 37079526
                },
                "scriptsig": "",
                "scriptsig_asm": "",
                "witness": [
                    "30440220780ad409b4d13eb1882aaf2e7a53a206734aa302279d6859e254a7f0a7633556022011fd0cbdf5d4374513ef60f850b7059c6a093ab9e46beb002505b7cba0623cf301",
                    "022bf8c45da789f695d59f93983c813ec205203056e19ec5d3fbefa809af67e2ec"
                ],
                "is_coinbase": False,
                "sequence": 4294967295
            }
        ],
        "vout": [
            {
                "scriptpubkey": "76a9146085312a9c500ff9cc35b571b0a1e5efb7fb9f1688ac",
                "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 6085312a9c500ff9cc35b571b0a1e5efb7fb9f16 OP_EQUALVERIFY OP_CHECKSIG",
                "scriptpubkey_type": "p2pkh",
                "scriptpubkey_address": "19oMRmCWMYuhnP5W61ABrjjxHc6RphZh11",
                "value": 100000
            },
            {
                "scriptpubkey": "0014ad4cc1cc859c57477bf90d0f944360d90a3998bf",
                "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 ad4cc1cc859c57477bf90d0f944360d90a3998bf",
                "scriptpubkey_type": "v0_p2wpkh",
                "scriptpubkey_address": "bc1q44xvrny9n3t5w7lep58egsmqmy9rnx9lt6u0tc",
                "value": 36977942
            }
        ]
    }

    transactions = [transaction_json]
    version = 1
    prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # Placeholder for previous block hash
    time = 1616832179  # Placeholder for block time
    nBits = 0x1d00ffff  # Placeholder for nBits
    nonce = 0  # Placeholder for nonce

    merkle_root = calculate_merkle_root(transactions)

    block_header = serialize_block_header(version, prev_block_hash, merkle_root, time, nBits, nonce)

    with open('output.txt', 'w') as output_file:
        output_file.write(block_header.hex() + '\n')
        output_file.write(json.dumps(transaction_json) + '\n')

    print("Output file 'output.txt' generated successfully.")

if __name__ == "__main__":
    main()
