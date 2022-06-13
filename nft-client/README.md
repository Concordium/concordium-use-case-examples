# NFT-client

This is an example of an off-chain application which integrates with a smart contract on chain. The application is a client for working with a Non-fungible token(NFT) smart contract.
The smart contract must follow the CIS2 specification, but for some of the functionality; additional assumptions are made for how the contract serializes the state and the existence of a "mint" contract function.

An example of a smart contract where all of the functionality is supported is called ``cis2-nft`` and can be found [here](https://github.com/Concordium/concordium-rust-smart-contracts/tree/main/examples).

Most of the functionality needs access to the GRPC API of a running concordium-node.
Some functionality of the client additionally depends on the concordium-node to have the [transaction logging enabled](https://github.com/Concordium/concordium-node/blob/main/docs/transaction-logging.md) and access to
the PostgreSQL database with transaction logs.

Run the following for a description of the functionality:

```
nft-client --help
```

Token IDs consists of bytes and are supplied and displayed hex encoded. Meaning the token IDs ``[10]`` and ``[10, 190]`` are encoded as `0a` and `0abe` respectively.

## Commands

The NFT-client supports the following commands:

### Minting NFTs

Call the smart contract function for minting a number of NFTs with provided token IDs.
This command will result in a transaction on the blockchain and requires account keys, see section for setting up account keys.

This command will **not** work for any CIS2 smart contract, because the function for minting is not part of the specification.

Notice the smart contract will only allow the contract owner to call the mint function.

#### Example:

To mint two NFTs with tokenID `0a` and `0abe`; run the following command:
```
nft-client mint --contract "<54,0>" --sender key-test.json 0a 0abe
```


### Transferring NFTs

Call the smart contract function for transferring specified tokens from one account to another.
This command will result in a transaction on the blockchain and requires account keys, see section for setting up account keys.

#### Example:

To transfer two NFTs with tokenID `0a` and `0abe` (hex encoded) we can run the following command
```
nft-client transfer --contract "<54,0>" --sender key-test.json --from "4RgTGQhg1Y8DAUkC2TpZsKmXdicArDqY9gcgJmBDECg4kkYNg4" --to "3UiNwnmZ64YR423uamgZyY8RnRkD88tfn6SYtKzvWZCkyFdN94" --token 0a --token 0abe
```


### Show current state of the NFT contract

Fetches the current state of the smart contract and displays the current NFT owners and the token IDs they own and enabled operators.

Since CIS2 does not specify how to serialize the contract state, this will only work for smart contracts using the exact same serialization as the "CIS2-NFT" example.

To show the current state of the smart contract run:
```
nft-client show --contract "<54,0>"
```


### Trace the CIS2 contract events

Requires node transaction logging to be setup with a PostgreSQL database.

To trace the events of the smart contract run:
```
nft-client trace-events --contract "<54,0>"
```


## Setup account keys

You will need the account keys of some account on the chain, with sufficient GTU.
These keys have to be in the same format as produced by the `genesis` tool, i.e.,

```json
{
  "accountKeys": {
    "keys": {
      "0": {
        "keys": {
          "0": {
            "signKey": "a58b777e96911c0f4cdce5f523ceacfaca6a6cd933e45d2912539604818bfe0d",
            "verifyKey": "b2a8fa68eac398ecfb2543b8b6c94517d3a85a38b820d702d4463e0993967d8d"
          },
          "1": {
            "signKey": "f6e15e8278c3085715d894de2f2189d699142ce8bbaada18f164c72d829f1f86",
            "verifyKey": "dd9adc691a404bd5dbebda126b8d188d65805c24275e878ac7d6f12375447735"
          },
          "2": {
            "signKey": "518a5f602358d870978d596e65ff4f49c2b5ab0451858daa384f658d3d0ef037",
            "verifyKey": "de22cc7f4d52f1e86c0189782c96612159f0ebde89e8cc5295d805f06fb7fb0c"
          }
        },
        "threshold": 2
      }
    },
    "threshold": 1
  },
  "address": "2zxYysSkpQ8Yop1fUuiSuxYngc4w64LFDiuQ8vMK71U47uyUkk"
}
```
