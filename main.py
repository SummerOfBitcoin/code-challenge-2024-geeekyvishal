import hashlib
import json
import struct
import time

def serialize_block_header(version, prev_block_hash, merkle_root, time, nBits, nonce):
    # Serialize the block header according to the format described
    block_header = (
        struct.pack('<L', version) +
        bytes.fromhex(prev_block_hash)[::-1] +
        bytes.fromhex(merkle_root)[::-1] +
        struct.pack('<L', time) +
        struct.pack('<L', nBits) +
        struct.pack('<L', nonce)
    )
    return block_header.hex()

def main():
    # Block header parameters
    version = 1
    prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    merkle_root = "0000000000000000000000000000000000000000000000000000000000000000"
    current_time = int(time.time())
    nBits = 0x1d00ffff
    nonce = 0

    # Serialized coinbase transaction
    coinbase_transaction = '{"txid": "coinbase", "vin": [{"coinbase": "Summer of Bitcoin 2024", "sequence": 0}], "vout": [{"value": 50, "recipient": "miner"}], "block_height": 8132, "fee": 0}\n'

    # Mined transaction IDs (txids)
    mined_txids = [
        "7919f94d93328389ae17b652b246ad092c883d17f69ce0e7f9367aa199884d4e",
        "8f0282cbfd690ba56111e4bdd1f1193fe6ec5f0f2488a6b88495a8affa4c5b3b",
        "c3fc0eb3675a6ce1ea836682b6a696fa10a4776077bf2fb0c9104dc220a58137",
        "9653ffaeffe71d5315a0eb454d3c80801e93e52ae9a438b8cd0ca9dc540da7b6",
        "882d6be89e429714beb8d30d7f8cadd58aa7703108fe1d0c554f15f18227637d",
        "cf3b93ea1ff5f685d045ee53ca8d82a19b20fa608458e840b2802f2a427f16fa",
        "942b846a6c929b6b5490bd240f4c3700b5570f6269afd752386da2742273059c"
    ]

    # Serialize block header
    block_header = serialize_block_header(version, prev_block_hash, merkle_root, current_time, nBits, nonce)

    # Write data to output.txt
    with open('output.txt', 'w') as output_file:
        # Write block header
        output_file.write(block_header + '\n')

        # Write serialized coinbase transaction
        output_file.write(coinbase_transaction)

        # Write mined transaction IDs
        for txid in mined_txids:
            output_file.write(txid + '\n')

    print("Output file 'output.txt' generated successfully.")

if __name__ == "__main__":
    main()
