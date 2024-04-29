import hashlib
import json
import os
import time

TARGET = int('0000ffff00000000000000000000000000000000000000000000000000000000', 16)
MAX_BLOCK_SIZE = 1000000  # Maximum block size in bytes

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

def extract_txid(transaction):
    if 'txid' in transaction:
        return transaction['txid']
    elif 'vin' in transaction and transaction['vin']:
        return transaction['vin'][0].get('txid')
    elif 'vout' in transaction and transaction['vout']:
        return transaction['vout'][0].get('txid')
    return None

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
        "vin": [{"coinbase": coinbase_message, "sequence": 0}],
        "vout": [{"value": 50, "recipient": "miner"}],
        "block_height": block_height,
        "fee": 0
    }

def mine_block(transactions):
    # Existing code...
    
    version = 1
    prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    bits = "1d00ffff"
    timestamp = int(time.time())
    nonce = 0

    # Build Merkle root
    txids.append(coinbase_txid)
    merkle_root = build_merkle_root(txids)

    # Build block header
    block_header_data = (
        f"{version:08x}"
        f"{prev_block_hash}"
        f"{merkle_root}"
        f"{bits}"
        f"{timestamp:08x}"
        f"{nonce:08x}"
    )

    while True:
        block_header = hash_sha256(block_header_data)
        if int(block_header, 16) < TARGET:
            break
        nonce += 1
        block_header_data = (
            f"{version:08x}"
            f"{prev_block_hash}"
            f"{merkle_root}"
            f"{bits}"
            f"{timestamp:08x}"
            f"{nonce:08x}"
        )

    return block_header, block_transactions, total_fees


def main():
    mempool_path = 'mempool'
    
    try:
        transactions = []
        for filename in os.listdir(mempool_path):
            with open(os.path.join(mempool_path, filename), 'r') as file:
                transactions.append(json.load(file))

        block_header, block_transactions, total_fees = mine_block(transactions)

        with open('output.txt', 'w') as output_file:
            if len(block_header) != 64:
                raise ValueError("Invalid block header length")

            output_file.write(block_header + '\n')

            coinbase_transaction_serialized = json.dumps(block_transactions[0])
            if len(coinbase_transaction_serialized) > MAX_BLOCK_SIZE:
                raise ValueError("Coinbase transaction size exceeds maximum block size")

            output_file.write(coinbase_transaction_serialized + '\n')

            for transaction in block_transactions[1:]:
                txid = extract_txid(transaction)
                if txid:
                    output_file.write(txid + '\n')

            output_file.write('Total fees: {}\n'.format(total_fees))

        print("Output file 'output.txt' generated successfully.")

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
