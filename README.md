# Merkle Airdrop

This is a merkle airdrop smart contract that works with Mass airdrop distributions made cheap
and efficient. It is a modified version of [cw20-merkle-airdrop](https://github.com/CosmWasm/cw-tokens/tree/main/contracts/cw20-merkle-airdrop)

Explanation of merkle
airdrop: [Medium Merkle Airdrop: the Basics](https://medium.com/smartz-blog/merkle-airdrop-the-basics-9a0857fcc930)

Traditional and non-efficient airdrops:

- Distributor creates a list of airdrop
- Sends bank send messages to send tokens to recipients

**Or**

- Stores list of recipients on smart contract data
- Recipient claims the airdrop

These two solutions are very ineffective when recipient list is big. First, costly because bank send cost for the
distributor will be costly. Second, whole airdrop list stored in the state, again costly.

Merkle Airdrop is very efficient even when recipient number is massive.

This contract works with multiple airdrop rounds, meaning you can execute several airdrops using same instance.

Uses **SHA256** for merkle root tree construction.

## Procedure

- Distributor of contract prepares a list of addresses with many entries and publishes this list in public static .js
  file in JSON format
- Distributor reads this list, builds the merkle tree structure and writes down the Merkle root of it.
- Distributor creates contract and places calculated Merkle root into it.
- Distributor says to users, that they can claim their tokens, if they owe any of addresses, presented in list,
  published on distributor's site.
- User wants to claim his N tokens, he also builds Merkle tree from public list and prepares Merkle proof, consisting
  from log2N hashes, describing the way to reach Merkle root
- User sends transaction with Merkle proof to contract
- Contract checks Merkle proof, and, if proof is correct, then sender's address is in list of allowed addresses, and
  contract does some action for this use.
- Distributor sends token to the contract, and registers new merkle root for the next distribution round.

## Merkle Airdrop CLI

[Merkle Airdrop CLI](helpers) contains js helpers for generating root, generating and verifying proofs for given airdrop
file.

## Test Vector Generation

Test vector can be generated using commands at [Merkle Airdrop CLI README](helpers/README.md)
