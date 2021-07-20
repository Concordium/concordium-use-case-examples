# Sending metadata with transfers

This example illustrates how to use a "memo" smart contract as an intermediary
between two accounts to send transfers with additional metadata. The example
illustrated here works in combination with the
[memo](https://github.com/Concordium/concordium-rust-smart-contracts/tree/main/examples/memo)
smart contract.

The setup is as follows. An account `$EXCHANGE` wishes to receive transfers from
other accounts, but to identify different transfers they want the transfers to
come with an identifier. In this example the identifier is an arbitrary 32-byte
array.

To achieve this the `$EXCHANGE` account deploys an instance of the
[memo](https://github.com/Concordium/concordium-rust-smart-contracts/tree/main/examples/memo)
smart contract to address `$CONTRACT`
other accounts, instead of sending transfers directly to `$EXCHANGE`, send
transfers with the identifier to `$CONTRACT` instead.

All the contract does is check that the sender included an identifier and
forwards the received GTU to the owner account, which is `$EXCHANGE`. In the
transaction summary the identifier can be observed and the receiver can identify
the sender.

## Contract deployment

The contract can be deployed and initialized with
[concordium-client](https://developer.concordium.software/en/mainnet/net/references/concordium-client.html)
as follows.
```console
concordium-client module deploy --sender $EXHANGE memo.wasm --name memo
```
and then initialize from the deployed module
```console
concordium-client contract init memo --contract memo --energy 10000 --sender $EXCHANGE
```
or a modification of these commands if a files are named differently, or the
node is reachable in a different way. This will initialize a new smart contract
instance on a fresh address `$CONTRACT`.

## Service description

The small service demonstrated here is a companion to the smart contract that
demonstrates how to monitor the contract and retrieve the identifiers. It
exposes three endpoints

### GET /wallet

This is an test endpoint that serves as the wallet that sends well-formed
transfers through the intermediate smart contract.


### POST /submit

Is an endpoint where the wallet submits the transfer request.

### GET /observe

Is where one can observe transfers that have been sent to a smart contract. It
supports the following query parameters

- `index: u64`, the index of a smart contract to query (defaults to 0)
- `subindex: u64`, the subindex of a smart contract to query (defaults to 0)
- `filter: bool`, whether to display only the updates of the contract, and also
  in a streamlined way with only the minimal information necessary. Defaults to `false`.

The `index` and `subindex` together form the smart contract address.

# Service dependencies

The service needs access to

- a node via the GRPC interface
- a PostgreSQL database with transaction logging
- account keys of some account on the chain, with sufficient GTU. These keys
  have to be in the same format as produced by the `genesis` tool, i.e.,
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

Then to run the service do
```console
cargo run -- --account keys.json --node http://localhost:7000
```
To override the database connection string use the `--db` flag, and in general use `--help` to get the list of all options and their defaults.
