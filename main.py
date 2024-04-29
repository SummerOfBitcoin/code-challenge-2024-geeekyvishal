import hashlib
import json
import os
import time

TARGET = int('0000ffff00000000000000000000000000000000000000000000000000000000', 16)
MAX_BLOCK_SIZE = 1000000  # Maximum block size in bytes

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def validate_transaction(transaction, spent_txids):
    # Extract txid from vin or vout
    txid = None
    if 'vin' in transaction and transaction['vin']:
        txid = transaction['vin'][0].get('txid')
    elif 'vout' in transaction and transaction['vout']:
        txid = transaction['vout'][0].get('txid')
    
    if txid is None:
        return False

    if txid in spent_txids:
        return False

    # Add txid to spent_txids to prevent double spending
    spent_txids.add(txid)

    # Check if the transaction has a fee field
    if 'fee' not in transaction:
        return False

    return True


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
    transactions.sort(key=lambda x: x.get('fee', 0), reverse=True)

    for transaction in transactions:
        if block_size >= MAX_BLOCK_SIZE:
            break
        if validate_transaction(transaction, spent_txids):
            transaction_size = calculate_transaction_size(transaction)
            if block_size + transaction_size <= MAX_BLOCK_SIZE:
                total_fees += transaction['fee']
                block_transactions.append(transaction)
                spent_txids.add(transaction['txid'])
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

    while True:
        block_header_data = str(version) + prev_block_hash + merkle_root + bits + str(timestamp) + str(nonce)
        block_header = hash_sha256(block_header_data)
        if int(block_header, 16) < TARGET:
            break
        nonce += 1

    # Add nonce to block header data
    block_header_data = str(version) + prev_block_hash + merkle_root + bits + str(timestamp) + str(nonce)

    return block_header_data, block_transactions, total_fees





def main():
    # Get the directory of the script file
    script_dir = os.path.dirname(__file__)
    mempool_path = os.path.join(script_dir, 'mempool')

    try:
        transactions = []
        for filename in os.listdir(mempool_path):
            with open(os.path.join(mempool_path, filename), 'r') as file:
                transactions.append(json.load(file))

        block_header, block_transactions, total_fees = mine_block(transactions)

        with open('output.txt', 'w') as output_file:
            # Check block header length
            if len(block_header) != 64:
                raise ValueError("Invalid block header length")

            # Write the block header
            output_file.write(block_header + '\n')

            # Serialize and check the length of the coinbase transaction
            coinbase_transaction_serialized = json.dumps(block_transactions[0])
            if len(coinbase_transaction_serialized) > MAX_BLOCK_SIZE:
                raise ValueError("Coinbase transaction size exceeds maximum block size")

            # Write the serialized coinbase transaction
            output_file.write(coinbase_transaction_serialized + '\n')

            # Write the transaction IDs of the mined transactions
            for transaction in block_transactions[1:]:
                txid = transaction.get('txid')
                if txid:
                    output_file.write(txid + '\n')

            # Write total fees
            output_file.write('Total fees: {}\n'.format(total_fees))

        print("Output file 'output.txt' generated successfully.")

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()

