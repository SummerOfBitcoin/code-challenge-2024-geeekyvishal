import hashlib
import json
import os
import time
import struct

TARGET = int('0000ffff00000000000000000000000000000000000000000000000000000000', 16)
MAX_BLOCK_SIZE = 1000000  # Maximum block size in bytes

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def calculate_transaction_size(transaction):
    # Simple calculation of transaction size based on length of serialized JSON
    return len(json.dumps(transaction))

def extract_txid(transaction):
    # For simplicity, we'll just hash the serialized transaction data
    return hash_sha256(json.dumps(transaction))

def build_merkle_root(txids):
    if len(txids) == 0:
        return hash_sha256('')
    if len(txids) == 1:
        return txids[0]

    # Recursively build Merkle tree
    intermediate_hashes = [hash_sha256(txids[i] + txids[i+1]) for i in range(0, len(txids), 2)]
    return build_merkle_root(intermediate_hashes)

def build_coinbase_transaction(coinbase_message, block_height):
    return {
        "txid": "coinbase",
        "vin": [{
            "coinbase": coinbase_message,
            "sequence": 0
        }],
        "vout": [{
            "value": 50,  # Initial block reward
            "recipient": "miner"
        }],
        "block_height": block_height,
        "fee": 0
    }

def calculate_header(transaction):
    # Hash the fields
    version_hash = hashlib.sha256(str(transaction['version']).encode()).hexdigest()
    locktime_hash = hashlib.sha256(str(transaction['locktime']).encode()).hexdigest()
    vin_hash = hashlib.sha256(json.dumps(transaction['vin']).encode()).hexdigest()
    vout_hash = hashlib.sha256(json.dumps(transaction['vout']).encode()).hexdigest()

    # Concatenate the hashed values
    concatenated = version_hash + locktime_hash + vin_hash + vout_hash

    # Ensure the concatenated string is exactly 80 bytes long
    header = concatenated[:80].ljust(80, '0')

    return header

def calculate_transaction_fee(transaction):
    input_value = sum([vin['prevout']['value'] for vin in transaction['vin']])
    output_value = sum([vout['value'] for vout in transaction['vout']])
    return input_value - output_value

def mine_block(transactions):
    block_transactions = []
    spent_txids = set()
    total_fees = 0
    block_size = 0
    txids = []

    # Build coinbase transaction
    coinbase_message = "Summer of Bitcoin 2024"
    coinbase_transaction = build_coinbase_transaction(coinbase_message, len(transactions) + 1)
    coinbase_txid = extract_txid(coinbase_transaction)
    block_transactions.append(coinbase_transaction)
    spent_txids.add(coinbase_transaction['txid'])
    block_size += calculate_transaction_size(coinbase_transaction)

    # Sort transactions by fee (high to low)
    transactions.sort(key=lambda x: calculate_transaction_fee(x), reverse=True)

    for transaction in transactions:
        if block_size >= MAX_BLOCK_SIZE:
            break
        transaction_size = calculate_transaction_size(transaction)
        if block_size + transaction_size <= MAX_BLOCK_SIZE:
            total_fees += calculate_transaction_fee(transaction)
            block_transactions.append(transaction)
            spent_txids.add(extract_txid(transaction))
            block_size += transaction_size
            txids.append(extract_txid(transaction))

    # Build Merkle root
    txids.append(coinbase_txid)
    merkle_root = build_merkle_root(txids)

   # Build block header
    version = 1
    prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # Placeholder for previous block hash
    bits = "1d00ffff"  # Placeholder for bits
    timestamp = int(time.time())  # Current timestamp
    nonce = 0

    # Pack block header data into a byte string
    block_header_data = struct.pack("<L", version) + bytes.fromhex(prev_block_hash) + bytes.fromhex(merkle_root) + bytes.fromhex(bits) + struct.pack("<L", timestamp) + struct.pack("<L", nonce)

    while True:
        block_header_hash = hashlib.sha256(hashlib.sha256(block_header_data).digest()).digest()
        if int.from_bytes(block_header_hash, "big") < TARGET:
            break
        nonce += 1
        block_header_data = struct.pack("<L", version) + bytes.fromhex(prev_block_hash) + bytes.fromhex(merkle_root) + bytes.fromhex(bits) + struct.pack("<L", timestamp) + struct.pack("<L", nonce)

    # Convert block header data to hexadecimal string
    block_header = block_header_hash.hex()

    return block_header, block_transactions, total_fees


def main():
    script_dir = os.path.dirname(__file__)
    mempool_path = os.path.join(script_dir, 'mempool')

    try:
        transactions = []
        for filename in os.listdir(mempool_path):
            with open(os.path.join(mempool_path, filename), 'r') as file:
                transactions.append(json.load(file))

        block_header, block_transactions, total_fees = mine_block(transactions)

        with open('output.txt', 'w') as output_file:
            output_file.write(block_header + '\n')
            output_file.write(json.dumps(block_transactions[0]) + '\n')
            for transaction in block_transactions[1:]:
                output_file.write(extract_txid(transaction) + '\n')
            output_file.write('Total fees: {}\n'.format(total_fees))

        print("Output file 'output.txt' generated successfully.")

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
