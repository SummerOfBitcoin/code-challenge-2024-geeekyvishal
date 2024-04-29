import hashlib
import json
import os
import struct
import time

TARGET = int('0000ffff00000000000000000000000000000000000000000000000000000000', 16)
MAX_BLOCK_SIZE = 1000000

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def validate_transaction(transaction, spent_txids):
    txid = None
    if 'vin' in transaction and transaction['vin']:
        txid = transaction['vin'][0].get('txid')
    elif 'vout' in transaction and transaction['vout']:
        txid = transaction['vout'][0].get('txid')
    
    if txid is None:
        return False

    if txid in spent_txids:
        return False

    spent_txids.add(txid)

    if 'fee' not in transaction:
        return False

    return True

def calculate_transaction_size(transaction):
    return len(json.dumps(transaction))

def extract_txid(transaction):
    return hash_sha256(json.dumps(transaction))

def build_merkle_root(txids):
    if len(txids) == 0:
        return hash_sha256('')
    if len(txids) == 1:
        return txids[0]

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
            "value": 50,
            "recipient": "miner"
        }],
        "block_height": block_height,
        "fee": 0
    }

def serialize_block_header(version, prev_block_hash, merkle_root, time, nBits, nonce):
    return (
        struct.pack('<L', version) +
        bytes.fromhex(prev_block_hash) +
        bytes.fromhex(merkle_root) +
        struct.pack('<L', time) +
        struct.pack('<L', nBits) +
        struct.pack('<L', nonce)
    )

def mine_block(transactions):
    block_transactions = []
    spent_txids = set()
    total_fees = 0
    block_size = 0
    txids = []

    coinbase_message = "Summer of Bitcoin 2024"
    coinbase_transaction = build_coinbase_transaction(coinbase_message, len(transactions) + 1)
    coinbase_txid = extract_txid(coinbase_transaction)
    block_transactions.append(coinbase_transaction)
    spent_txids.add(coinbase_transaction['txid'])
    block_size += calculate_transaction_size(coinbase_transaction)

    transactions.sort(key=lambda x: x.get('fee', 0), reverse=True)

    for transaction in transactions:
        if block_size >= MAX_BLOCK_SIZE:
            break
        if validate_transaction(transaction, spent_txids):
            transaction_size = calculate_transaction_size(transaction)
            if block_size + transaction_size <= MAX_BLOCK_SIZE:
                total_fees += transaction.get('fee', 0)
                block_transactions.append(transaction)
                spent_txids.add(transaction['txid'])
                block_size += transaction_size
                txids.append(extract_txid(transaction))

    txids.append(coinbase_txid)
    merkle_root = build_merkle_root(txids)

    version = 1
    prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    time_stamp = int(time.time())
    nBits = 0x1bc330
    nonce = 0

    block_header_data = serialize_block_header(version, prev_block_hash, merkle_root, time_stamp, nBits, nonce)

    while True:
        block_header_hash = hashlib.sha256(hashlib.sha256(block_header_data).digest()).digest()
        if int.from_bytes(block_header_hash, "big") < TARGET:
            break
        nonce += 1
        block_header_data = serialize_block_header(version, prev_block_hash, merkle_root, time_stamp, nBits, nonce)

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
