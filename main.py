#!/usr/bin/env python3
import argparse
import datetime
import sys

import requests
import eth_keys
from eth_keys.datatypes import Signature
import rlp
from Crypto.Hash import keccak
from enum import Enum
from concurrent.futures import ProcessPoolExecutor

import json
import os

# CoinCurveECCBackend backend is way faster than NativeECCBackend
os.environ['ECC_BACKEND_CLASS'] = 'eth_keys.backends.CoinCurveECCBackend'


# Ethereum versions

class EthereumProtocolVersion(Enum):
    FRONTIER = 0
    HOMESTEAD = 1_150_000
    TANGERINE_WHISTLE = 2_463_000
    SPURIOUS_DRAGON = 2_675_000
    BYZANTIUM = 4_370_000
    CONSTANTINOPLE = 7_280_000
    PETERSBURG = 7_280_000
    ISTANBUL = 9_069_000
    MUIR_GLACIER = 9_200_000
    BERLIN = 12_244_000
    LONDON = 12_965_000
    ARROW_GLACIER = 13_773_000
    GRAY_GLACIER = 15_050_000

    def is_london(self):
        return self.value >= EthereumProtocolVersion.LONDON.value

    def is_berlin(self):
        return self.value >= EthereumProtocolVersion.BERLIN.value

    def is_spurious_dragon(self):
        return self.value >= EthereumProtocolVersion.SPURIOUS_DRAGON.value

    def is_homestead(self):
        return self.value >= EthereumProtocolVersion.HOMESTEAD.value


class TxParser:

    def get_message_hash(self, tx, *args, **kwargs) -> bytes:
        m = self.get_message(tx, *args, **kwargs)
        rlp_encoded = rlp.encode(m)
        keccak256 = keccak.new(digest_bits=256)
        keccak256.update(rlp_encoded)
        h = keccak256.digest()
        return h

    def get_message(self, tx, *args, **kwargs):
        raise Exception("Override me!")

    def get_signature_values(self, tx):
        raise Exception("Override me!")


class FrontierTxParser(TxParser):

    def get_message(self, tx, *args, **kwargs):
        nonce = int(tx["nonce"], 16)
        gas_price = int(tx["gasPrice"], 16)
        gas = int(tx["gas"], 16)

        to_raw = tx["to"]
        if to_raw is not None:
            to = bytes.fromhex(to_raw[2:])
        else:
            to = bytes()
        value = int(tx["value"], 16)
        data = bytes.fromhex(tx["input"][2:])
        m = (nonce, gas_price, gas, to, value, data)
        return m

    def get_signature_values(self, tx) -> (int, int, int):
        tx_type = int(tx["type"], 16)

        if tx_type == 0:
            # legacy transaction:
            # should have a "w" field, combining the chainId and yParity in a single value
            # it should be T_w = 27 + T_y
            # or           T_w = 2*Beta + 35 + T_y
            # where Beta is the network chain ID
            v = int(tx["v"], 16)

            if v in [27, 28]:
                v = v - 27
            elif v >= 35:
                v = (v - 35) % 2
            else:
                raise Exception(f"Failed to compute v")
        elif tx_type == 1:
            # EIP-2930 transaction
            # should have extra fields "accessList", "chainId" and "yParity"
            v = int(tx["yParity"], 16)

        r = int(tx["r"], 16)
        s = int(tx["s"], 16)

        return r, s, v


class HomesteadTxParser(TxParser):

    def __init__(self, frontier_parser):
        self.frontier: FrontierTxParser = frontier_parser

    def get_message(self, tx, *args, **kwargs):
        return self.frontier.get_message(tx, *args, **kwargs)

    def get_signature_values(self, tx):
        return self.frontier.get_signature_values(tx)


class SpuriousDragonEIP155TxParser(TxParser):

    def get_message(self, tx, *args, **kwargs):
        nonce = int(tx["nonce"], 16)
        gas_price = int(tx["gasPrice"], 16)
        gas = int(tx["gas"], 16)

        to_raw = tx["to"]
        if to_raw is not None:
            to = bytes.fromhex(to_raw[2:])
        else:
            to = bytes()
        value = int(tx["value"], 16)
        data = bytes.fromhex(tx["input"][2:])
        chain_id = 1

        v = int(tx["v"], 16)

        if v in [27, 28]:
            m = (nonce, gas_price, gas, to, value, data)
        else:
            m = (nonce, gas_price, gas, to, value, data, chain_id, 0, 0)

        return m

    def get_signature_values(self, tx):
        tx_type = int(tx["type"], 16)

        if tx_type == 0:
            v = int(tx["v"], 16)

            if v in [27, 28]:
                v = v - 27
            elif v >= 35:
                v = (v - 35) % 2
            else:
                raise Exception(f"Failed to compute v")

        r = int(tx["r"], 16)
        s = int(tx["s"], 16)

        return r, s, v


class BerlinEIP2930Parser(TxParser):

    def __init__(self, spurious_dragon_parser: SpuriousDragonEIP155TxParser):
        self.spurious_dragon = spurious_dragon_parser

    def get_message_hash(self, tx, *args, **kwargs) -> bytes:
        m = self.get_message(tx, *args, **kwargs)
        tx_type = int(tx["type"], 16)
        rlp_encoded = rlp.encode(m)
        keccak256 = keccak.new(digest_bits=256)
        if tx_type >= 1:
            keccak256.update(tx_type.to_bytes(1, byteorder="little"))
        keccak256.update(rlp_encoded)
        h = keccak256.digest()
        return h

    def get_message(self, tx, *args, **kwargs):
        tx_type = int(tx["type"], 16)

        nonce = int(tx["nonce"], 16)
        gas_price = int(tx["gasPrice"], 16)
        gas = int(tx["gas"], 16)

        to_raw = tx["to"]
        if to_raw is not None:
            to = bytes.fromhex(to_raw[2:])
        else:
            to = bytes()
        value = int(tx["value"], 16)
        data = bytes.fromhex(tx["input"][2:])
        chain_id = 1

        if tx_type == 0:
            # Legacy tx
            v = int(tx["v"], 16)

            if v in [27, 28]:
                m = (nonce, gas_price, gas, to, value, data)
            else:
                m = (nonce, gas_price, gas, to, value, data, chain_id, 0, 0)
        elif tx_type == 1:
            # Access list tx
            access_list = tx["accessList"]
            ta = []
            for e in access_list:
                addr = e["address"]
                addr = bytes.fromhex(addr[2:])
                storage_keys = e["storageKeys"]
                storage_keys = [bytes.fromhex(k[2:]) for k in storage_keys]
                ta.append((addr, storage_keys))
            m = (chain_id, nonce, gas_price, gas, to, value, data, ta)
        else:
            raise Exception("Berlin unsupported tx type")

        return m

    def get_signature_values(self, tx):
        tx_type = int(tx["type"], 16)

        if tx_type == 0:
            return self.spurious_dragon.get_signature_values(tx)
        elif tx_type == 1:
            # EIP-2930 transaction
            # should have extra fields "accessList", "chainId" and "yParity"
            v = int(tx["v"], 16)
            r = int(tx["r"], 16)
            s = int(tx["s"], 16)
            return r, s, v

        raise Exception(f"Unsupported tx type {tx_type=}")


class LondonTxParser(TxParser):

    def __init__(self, berlin_signer: BerlinEIP2930Parser):
        self.berlin = berlin_signer

    def get_message_hash(self, tx, *args, **kwargs) -> bytes:
        m = self.get_message(tx, *args, **kwargs)
        tx_type = int(tx["type"], 16)
        rlp_encoded = rlp.encode(m)
        keccak256 = keccak.new(digest_bits=256)
        if tx_type >= 1:
            keccak256.update(tx_type.to_bytes(1, byteorder="little"))
        keccak256.update(rlp_encoded)
        h = keccak256.digest()
        return h

    def get_message(self, tx, *args, **kwargs):
        tx_type = int(tx["type"], 16)

        if not tx_type == 2:
            return self.berlin.get_message(tx)

        nonce = int(tx["nonce"], 16)
        _gas_price = int(tx["gasPrice"], 16)
        gas = int(tx["gas"], 16)

        to_raw = tx["to"]
        if to_raw is not None:
            to = bytes.fromhex(to_raw[2:])
        else:
            to = bytes()
        value = int(tx["value"], 16)
        data = bytes.fromhex(tx["input"][2:])
        chain_id = 1

        access_list = tx["accessList"]
        ta = []
        for e in access_list:
            addr = e["address"]
            addr = bytes.fromhex(addr[2:])
            storage_keys = e["storageKeys"]
            storage_keys = [bytes.fromhex(k[2:]) for k in storage_keys]
            ta.append((addr, storage_keys))

        gas_tip_cap = int(tx["maxPriorityFeePerGas"], 16)
        gas_fee_cap = int(tx["maxFeePerGas"], 16)
        m = (chain_id, nonce, gas_tip_cap, gas_fee_cap, gas, to, value, data, ta)

        return m

    def get_signature_values(self, tx):
        tx_type = int(tx["type"], 16)

        if not tx_type == 2:
            return self.berlin.get_signature_values(tx)

        v = int(tx["v"], 16)
        r = int(tx["r"], 16)
        s = int(tx["s"], 16)
        return r, s, v


def get_eth_version(block_number):
    if block_number < EthereumProtocolVersion.HOMESTEAD.value:
        return EthereumProtocolVersion.FRONTIER

    prev = EthereumProtocolVersion.FRONTIER
    for v in EthereumProtocolVersion:
        if block_number < v.value:
            return prev
        prev = v
    return v


def dump(start_block, end_block, dump_output_file, host):
    # Tunable parameters
    batch_size = 500  # number of blocks to ask the JSON RPC server at once
    blocks_per_chunk = batch_size  # print stats every chunk (in number of blocks)

    # state
    executor = ProcessPoolExecutor()
    start_time = datetime.datetime.utcnow()
    last_chunk_time = start_time
    batch_start = start_block
    total_tx_error_count = 0

    with open(dump_output_file, "w+") as fout:
        with executor as ex:
            for i in range(start_block, end_block):
                if i - batch_start >= batch_size:
                    total_tx_error_count = handle_batch(batch_start, ex, fout, i, total_tx_error_count, host)

                    # set batch_start for next batch
                    batch_start = i

                if i % blocks_per_chunk == 0:
                    print_stats(blocks_per_chunk, i, start_block, last_chunk_time, start_time, total_tx_error_count)
                    last_chunk_time = datetime.datetime.utcnow()

            # end for i in range
            print(f"Sending last batch", file=sys.stderr)
            total_tx_error_count = handle_batch(batch_start, ex, fout, i, total_tx_error_count, host)
            print_stats(blocks_per_chunk, i, start_block, last_chunk_time, start_time, total_tx_error_count)

        # end with executor
    # end with open

    end_time = datetime.datetime.utcnow()
    duration = end_time - start_time
    print(f"End time: {end_time} UTC")
    print(f"Duration: {duration}")
    print(f"Successfully dumped signatures to output file {dump_output_file}")
    return total_tx_error_count


def print_stats(blocks_per_chunk, i, start_block, last_chunk_time, start_time, total_tx_error_count):
    now = datetime.datetime.utcnow()
    blocks_from_start = i - start_block
    total_duration = (now - start_time).total_seconds()
    chunk_duration = (now - last_chunk_time).total_seconds()
    avg_blocks_per_second = round(blocks_from_start / total_duration, 2)
    imm_blocks_per_second = round(blocks_per_chunk / chunk_duration, 2)
    print(f"block number: {i}", file=sys.stderr)
    print(f"Average   blocks/s: {avg_blocks_per_second}", file=sys.stderr)
    print(f"Chunk     blocks/s: {imm_blocks_per_second}", file=sys.stderr)
    print(f"Total TX error count: {total_tx_error_count}", file=sys.stderr)
    print(f"Start time: {start_time} UTC", file=sys.stderr)


def handle_batch(batch_start, ex, fout, i, total_tx_error_count, host):
    # Send batch request
    r = range(batch_start, i)
    if len(r) == 0:
        return 0

    batch_result = get_blocks_by_numbers(r, host)
    futures = []
    for block in batch_result:
        block_result = block["result"]
        block_number = int(block_result["number"], 16)
        future = ex.submit(process_block_result, block_result, block_number)
        futures.append(future)

    for future in futures:
        res = future.result()
        results, tx_error_count = res
        total_tx_error_count += tx_error_count

        for result in results:
            # dump each result to output file
            from_address, r, s, pubkey, txid, message_hash, block_time = result
            output_line = f"{from_address};{r};{s};{pubkey};{txid};{message_hash};{block_time}\n"
            fout.write(output_line)
    return total_tx_error_count


def process_block_result(block_result, block_number):
    eth_protocol_version = get_eth_version(block_number)

    if eth_protocol_version.is_london():
        spurious = SpuriousDragonEIP155TxParser()
        berlin = BerlinEIP2930Parser(spurious)
        tx_parser = LondonTxParser(berlin)
    elif eth_protocol_version.is_berlin():
        spurious = SpuriousDragonEIP155TxParser()
        tx_parser = BerlinEIP2930Parser(spurious)
    elif eth_protocol_version.is_spurious_dragon():
        tx_parser = SpuriousDragonEIP155TxParser()
    elif eth_protocol_version.is_homestead():
        frontier = FrontierTxParser()
        tx_parser = HomesteadTxParser(frontier)
    else:
        tx_parser = FrontierTxParser()

    txs = block_result["transactions"]
    block_timestamp = int(block_result["timestamp"], 16)
    tx_error_count = 0
    results = []

    for tx in txs:
        # compute hash of message => defined in the yellow paper, appendix F (need to have keccak-256 and RLP functions)
        h = tx_parser.get_message_hash(tx)
        # compute signature values
        r, s, v = tx_parser.get_signature_values(tx)

        signature = Signature(vrs=(v, r, s))
        pubkey = eth_keys.keys.ecdsa_recover(h, signature)
        pubkey_hex = pubkey.to_compressed_bytes().hex()
        txid = tx["hash"]
        from_address = tx["from"]

        is_valid = is_valid_message(pubkey, tx)

        if not is_valid:
            print(f"Invalid message, {block_number=}, {txid=}")
            tx_error_count += 1
        else:
            result = (from_address, hex(r)[2:], hex(s)[2:], pubkey_hex, txid, h.hex(), block_timestamp)
            results.append(result)

    return results, tx_error_count


def is_valid_message(pubkey, tx):
    # To check that the message was properly computed, we take the public key
    # then we compute the wallet address
    # finally, we check that this computed address matches the address in the "from" field
    computed_addr = pubkey.to_checksum_address().lower()
    from_addr = tx["from"].lower()
    valid = computed_addr == from_addr  # Check that computation was correct
    return valid


def get_blocks_by_numbers(block_range, host):
    batch = []
    for block_number in block_range:
        data = {
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [hex(block_number), True],
            "id": 0
        }
        batch.append(data)
    batch_json = json.dumps(batch)
    ret = requests.post(host, data=batch_json, headers={"Content-type": "application/json"})
    ret_data = ret.json()
    return ret_data


def get_parser():
    parser = argparse.ArgumentParser(
        prog="ecdsa-dump-ethereum",
        description="Dump ECDSA signatures, original message, etc. of all transactions on the Ethereum blockchain."
    )
    parser.add_argument("--start-block", "-s", type=int, default=0, help="Number of the block to start dumping from",
                        dest="start_block")
    parser.add_argument("--end-block", "-e", type=int, default=70_000,
                        help="Number of the block to stop dumping from (included)",
                        dest="end_block")
    default_host = "http://localhost:8545"
    parser.add_argument("--host", type=str, default=default_host,
                        help=f"The Ethereum node JSON RPC service to connect to. Defaults to {default_host} .",
                        dest="host")
    parser.add_argument("--output", "-o", type=str, required=True,
                        help="Path to the output file to dump to",
                        dest="output_path")
    return parser


def check_connection(host):
    try:
        get_blocks_by_numbers(range(0, 1), host)
    except requests.exceptions.ConnectionError:
        print(f"Cannot connect to Ethereum node JSON RPC server at {host}")
        print(f"Is it running?")
        sys.exit(-1)


def main():
    parser: argparse.ArgumentParser = get_parser()
    args = parser.parse_args()

    check_connection(args.host)

    dump(
        args.start_block,
        args.end_block,
        args.output_path,
        args.host
    )


if __name__ == '__main__':
    main()
