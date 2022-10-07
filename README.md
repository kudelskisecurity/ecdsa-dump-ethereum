# ecdsa-dump-ethereum

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-green.svg)](https://docs.python.org/3.7/whatsnew/) [![License: GPL v3](https://img.shields.io/badge/license-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

Dump ECDSA signatures, original message, etc. of all transactions on the Ethereum blockchain.

# Requirements

* Poetry, see [Installation instructions](https://python-poetry.org/docs/#installation)
* Python 3.7+
* An Ethereum node running with the JSON RPC service accessible at http://localhost:8545

As per [Nodes and Clients](https://ethereum.org/en/developers/docs/nodes-and-clients/), since "The Merge", to obtain a
fully synced node, both an execution client, such as [geth](https://github.com/ethereum/go-ethereum),
and a consensus client, such as [lighthouse](https://github.com/sigp/lighthouse) is required.

As of October 2022, the full chain (full node, not archive node) requires about 1.6 TB of storage.
Doing a full sync from scratch to block 15'800'000 will take about 3 weeks.

# Running the Ethereum node

To start `geth`:

```
geth --syncmode full --http
```

To start `lighthouse`:

```
lighthouse bn --execution-endpoint http://localhost:8551 --execution-jwt ~/.ethereum/geth/jwtsecret --http --checkpoint-sync-url https://mainnet.checkpoint.sigp.io
```

# Usage

To dump the signatures and messages from block 0 to 70000 as CSV, run:

```
poetry install
poetry run python main.py -o output_file.csv --end-block 70000
```

The output file will contain on each line:

```
source_address;r;s;pubkey;txid;message_hash;block_time
```

For more options and help:

```
$ poetry run python main.py -h                
usage: ecdsa-dump-ethereum [-h] [--start-block START_BLOCK] [--end-block END_BLOCK] [--host HOST] --output OUTPUT_PATH

Dump ECDSA signatures, original message, etc. of all transactions on the Ethereum blockchain.

options:
  -h, --help            show this help message and exit
  --start-block START_BLOCK, -s START_BLOCK
                        Number of the block to start dumping from
  --end-block END_BLOCK, -e END_BLOCK
                        Number of the block to stop dumping from (included)
  --host HOST           The Ethereum node JSON RPC service to connect to. Defaults to http://localhost:8545 .
  --output OUTPUT_PATH, -o OUTPUT_PATH
                        Path to the output file to dump to
```

# License and Copyright

Copyright(c) 2023 Nagravision SA.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.