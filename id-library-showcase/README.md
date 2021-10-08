# ID Library Showcase
Here we demonstrate how to prove and verify properties about an identity behind an account, such as
- reveal an attribute,
- prove ownership of an account,
- prove that an attribute is in a range.

## Account key structure
An account is owned by one or more credential holders. Each credential holder has a `credential index` and its own set of keys used to sign transactions. Each account has a threshold indicating how many of the credential holders owning the account is needed for signing a transaction. The account keys of an account consist of all the keys of all the credential holders. When creating an account, the user creating it will be the only account owner and will always have credential index `0`. When a user - a credential holder of an account - wants to prove or reveal anything about the account, it is always with respect to its own credential index.

## Reveal attribute
When creating an account, the user can choose to reveal attributes publicly on chain, such as country of residence, identity document type and more.
If an attribute is not revealed when creating the account, a commitment of the attribute will instead appear on chain. 
The user can then choose to reveal an attribute inside one of the on-chain commitments. 

As an example, suppose that a user named `John Doe` has created an identity and a normal account (here, a normal account means a non-initial account) using the Concordium Mobile Wallet, say `3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd`. Then he can produce a proof
that the first name of the user is indeed `John` as follows:
1. Export wallet and place the file in the same directory as the `id-library-showcase` binary. 
2. Run the command
   ```console
   ./id-library-showcase reveal-attribute --attribute-tag "firstName" --proof-out reveal.json --account 3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd --credential-index 0 --wallet EXPORTFILE
   Enter password to decrypt with: 
   ```
   where `EXPORTFILE` is the wallet export file from step 1.

Executing the above command will produce the JSON file `reveal.json` with the content

```json
{
  "account": "3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd",
  "credential_index": 0,
  "claim": {
    "type": "AttributeOpening",
    "attributeTag": "firstName",
    "attribute": "John",
    "proof": "0f16b4125c48b3bba9fa528c4496948ff21b2517028ae9631c8e6a2ba2c12521"
  }
}
```
indicating that it claims to prove that the credential holder with credential index `0` on account `3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd` has first name `John`.

The proof can be verified using the command
```console
./id-library-showcase verify-claim --claim reveal.json --node http://127.0.0.1:10000
Result: true
```
This assumes that the verifier is running a local node at http://127.0.0.1:10000. The `verify-claim` command looks up the relevant on-chain information needed for verifying the proof, which, in this case, is the commitment to the first name that appears on chain. 

## Prove ownership of account
The user can prove to someone that it is among the owners of an account, or in other words, that the user is a specific credential holder of an account. 
This is an interactive process between the user and the verifier. The steps are
1. First, the user claims to be a credential holder of an account by running
    ```console
    ./id-library-showcase claim-account-ownership --account 3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd --credential-index 0 --claim-out ownership-claim.json
    ```
    This produces the JSON file `ownership-claim` with the content
    ```json
    {
    "account": "3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd",
    "credential_index": 0,
    "claim": {
        "type": "AccountOwnership"
        }
    }
    ```
    indicating that the user claims to be the credential holder with index `0` of account `3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd`.
2. The verifier runs the command
    ```console
    ./id-library-showcase verify-claim --claim ownership-claim.json --node http://127.0.0.1:10000
    Wrote challenge to file. Give challenge to prover.
    Enter the path to the proof [ownership-proof.json]
    ```
    This will produce a file called `ownership-challenge.json` that contains some random bytes.
    The verifier should now wait for the prover to produce a proof and keep the terminal as is.
3. After receiving `ownership-challenge.json` from the verifier, the user runs the command
    ```console
    ./id-library-showcase prove-ownership --account 3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd --credential-index 0 --challenge ownership-challenge.json --out ownership-proof.json --wallet export
    Enter password to decrypt with:
    ```
    This produces the file `ownership-proof.json` with the proof that the user owns the account.
4. The verifier now presses enter after receiving `ownership-proof.json` from the user. The console should look like
   ```console
    ./id-library-showcase verify-claim --claim ownership-claim.json --node http://127.0.0.1:10000
    Wrote challenge to file. Give challenge to prover.
    Enter the path to the proof: ownership-proof.json
    Result: true
   ``
   indicating that the proof was correct.


## Prove that an attribute is in a range
Similar to revealing an attribute, the user can prove that an attribute lies in range, for example that the user's birthday lies between two dates.
It could be that the user's real birthday is 1970/01/01 but only wants to reveal that its birthday lies between 1969/05/01 and 1981/04/17. 
This can be achieved by running the command
```console
./id-library-showcase prove-attribute-in-range --lower "19690501" --upper "19810417" --attribute-tag "dob" --proof-out rangeproof.json --account 3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd --credential-index 0 --node http://127.0.0.1:10001 --wallet export
Enter password to decrypt with:
```

This produces a file ``rangeproof.json`` with the content
```json
{
  "account": "3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd",
  "credential_index": 0,
  "claim": {
    "type": "AttributeInRange",
    "attributeTag": "dob",
    "lower": "19690501",
    "upper": "19810417",
    "proof": "a3f8b7bcb00860c7d1ef02984417edf3c536b3bc45356792aec60ca67fa2d85208b00d13083e5ad22e69cd82c421966eb05056f9dd39f47f75cce900c3fb22a39fb2089d5abc24d507ccc37c3f13b1c61544bc2af007b1ffada33d0ef921e38b86774ee8d4a253abd47c3b3c11381344f1a16010686fbee382040368e14e5f63dec86bffbc79de5aa285ea7df1d5bae99104b59ec6c72c21dc81ceeb3f9e055191cca63be0358f0080b75662f0c70640b42645ece83e74124f1d660c309f7a9224cb9b946cd0add677dc62c5cd6635cc242dad7d2a63793f4b4ee9c49fe1e2ea20358f217e3ac5853c174c864a284767f0a86e934c663a8abe61f44b619bfb9312ab1951c28d531dc4bc5f52b066310858bb58ef60c87db7fb65f8ddbca1842f00000007888e24f3aa5f1bd7ce37a952c4ba77a7f712ccf9b6948e057b818f7ebe5aeb4bd14d6ac860f35afb931a7c0a45d6276588b882884a895521a4b8fce2651f8a8152598e13b414930a000118f2158ed707600d0d8ca056f107af85f0d9fcd024f3b4da3c2dd39df3477040066d6b6730a46470847e2a53dc85cb063682a945bac80eb6dc80a1882e35c1683e94202ae322954b1f1ec7811492e34d0834c7a9dcdc75a25fc809129345ce1f2434d8007dcb3ecdb944770b5fdcb1885cfe09733acbad6733d83cf83680c3ef0ef0d45bdcd22a184376329da978d9f9d26e9e664877e2e1c6b9931bc0dd2780f50adc2dfc22a38bd86ed96657867ff9805776e8bb3b465fde602d7b3ce321296dc9a564ae5132a3aeed325984d210192bb3dedd142490fe138813aa7a5cce6253709ac1152f2c715243fcd9ea034949ad51fb61a5038534e014b901057692123eb961c362b9acd7b1f85032ad0f3667697d88ae0c172fdef12449b4fb7a88c2c76cc6772c073f5a19ed73c3752ad3331f76f88a720ab8aef878e48701f88304cae9809c99b4d3fd30b94df37dd0d6e7b5260aa2d796cbaf1c9ea34311e5a3c39d45ce209e148227cc8e02a3604696cac5de212ede6bf12aba0e6d2503d6694f6873982d43ca778a126a6a2f904652f6b72f49483626b4ff293f4187b3e9092994a68ef2e0dcebe6a89724c3bb0c4d496eabec6c2e680b3724d9af729ba348b44fed4804b2e9a2205433da9660a6182251b13880c9a9c76d36ee6ae66088b7d1c85e49ad0bf4e34407857b775e48f1142b4fa38c8d01b80cfaa42fb8286a16f763beda282362c1477bf64b16f5d002743c795966837c385c39c67566543102ecd0081830361384fbea73027969bd444d950a03e0d47c1b3e04a900533e3622871ab1c19ee772259ca229fdfbaa53ad01fab308dd467e211e7e8b9ba191305acbfb5d88eb362f21522e2181b3b03c3a1666d16d86689c70ec004227f8ddba02513e977e299fbf9edc7ba29a8dbe9cdd7ea2441cbfdfa5"
  }
}
```
indicating that the user claims that the credential holder with credential index `0` on account `3UHUEr3KkFG3pd6Zj3nH7hJfng9dpqwWPfSCuSwarw38diLLmd` was born between 1969/05/01 and 1981/04/17 (not including 1981/04/17).

The verifier can verify it by running
```console
./id-library-showcase verify-claim --claim rangeproof.json --node http://127.0.0.1:10001
Result: true
```
The above command checks the provided proof up against the on-chain commitment to the attribute (in this case the birthday). 
