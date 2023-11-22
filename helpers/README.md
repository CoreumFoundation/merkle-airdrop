merkle-airdrop-cli
==================

This is a helper client shipped along contract.
Use this to generate root, generate proofs and verify proofs

## Installation

```shell
yarn install
```

Binary will be placed to path.

## Airdrop file format

```json
[
  { "address": "wasm1k9hwzxs889jpvd7env8z49gad3a3633vg350tq", "amount": "100"},
  { "address": "wasm1uy9ucvgerneekxpnfwyfnpxvlsx5dzdpf0mzjd", "amount": "1010"}
]
```

## Commands

**Generate Root:**
```shell
./bin/run generateRoot --file ../testdata/airdrop_stage_1_list.json
```

**Generate proof:**
```shell
./bin/run generateProofs --file ../testdata/airdrop_stage_1_list.json \
  --address devcore1msa5mwyvjqlc4nj4ym2q8nqrs0dq9t6n55nejz \
  --amount 1000000
```

