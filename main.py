import hashlib
import json
import os

TARGET = int('0000ffff00000000000000000000000000000000000000000000000000000000', 16)

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def validate_transaction(transaction, spent_txids):
    if transaction['txid'] in spent_txids:
        return False
    if 'vin' not in transaction or 'vout' not in transaction:
        return False
    for vin in transaction['vin']:
        if vin['value'] < 0:
            return False
    return True

def mine_block(transactions):
    block_transactions = []
    spent_txids = set()
    total_fees = 0

    coinbase_transaction = {
        "tx_id": "coinbase",
        "sender": "",
        "recipient": "miner",
        "value": 50,
        "fee": 0
    }
    block_transactions.append(coinbase_transaction)
    spent_txids.add(coinbase_transaction['tx_id'])

    for transaction in transactions:
        if validate_transaction(transaction, spent_txids):
            total_fees += sum(vin['value'] for vin in transaction['vin'])
            block_transactions.append(transaction)
            spent_txids.add(transaction['txid'])

    block_transactions_serialized = json.dumps(block_transactions)

    block_header = hash_sha256(block_transactions_serialized)

    nonce = 0
    while True:
        block_hash = hash_sha256(block_header + str(nonce))
        if int(block_hash, 16) < TARGET:
            break
        nonce += 1

    block_header = block_header + str(nonce)

    return block_header, block_transactions_serialized, total_fees

def main():
    mempool_path = 'mempool/'
    transactions = []
    for filename in os.listdir(mempool_path):
        with open(os.path.join(mempool_path, filename), 'r') as file:
            transactions.append(json.load(file))

    block_header, block_transactions_serialized, total_fees = mine_block(transactions)

    with open('output.txt', 'w') as output_file:
        output_file.write(block_header + '\n')
        output_file.write(block_transactions_serialized + '\n')
        output_file.write('Total fees: {}'.format(total_fees))

if __name__ == "__main__":
    main()