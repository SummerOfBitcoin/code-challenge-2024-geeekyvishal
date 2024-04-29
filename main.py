import hashlib
import json
import os

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

def extract_txid(transaction):
    # Extract transaction ID (txid) from the transaction
    return transaction.get('txid')

def mine_block(transactions):
    block_transactions = []
    spent_txids = set()
    total_fees = 0
    block_size = 0
    txids = []

    for transaction in transactions:
        if block_size >= MAX_BLOCK_SIZE:
            break

        if validate_transaction(transaction, spent_txids):
            transaction_size = len(json.dumps(transaction))
            if block_size + transaction_size <= MAX_BLOCK_SIZE:
                total_fees += transaction['fee']
                block_transactions.append(transaction)
                spent_txids.add(transaction['txid'])
                block_size += transaction_size
                txids.append(extract_txid(transaction))

    return block_transactions, total_fees

def main():
    mempool_path = 'mempool'
    
    try:
        transactions = []
        for filename in os.listdir(mempool_path):
            with open(os.path.join(mempool_path, filename), 'r') as file:
                transactions.append(json.load(file))

        block_transactions, total_fees = mine_block(transactions)

        with open('output.txt', 'w') as output_file:
            # Write the serialized coinbase transaction
            for transaction in block_transactions:
                output_file.write(json.dumps(transaction) + '\n')

            # Write total fees
            output_file.write('Total fees: {}\n'.format(total_fees))

        print("Output file 'output.txt' generated successfully.")

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
