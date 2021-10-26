# Trace Account

This is an example of how one can use the output of the anonymity revocation tool, to generate a log of transactions of the accounts whose anonymity has been revoked. The log consists of one .csv file per traced account. If a decryption key is generated as part of anonymity revocation, then any encrypted amounts will appear decrypted in the log.

Run the following for a description of the functionality:

```
trace-account help
```

The tool needs access to a transaction database and a grpc endpoint. 
If you are not running a node matching the default values, these must be provided through the options `db` and `node`.
The default values are shown with the help command.

## Commands

The trace account tool supports the following commands:

### All

To use the tool with the output of anonymity revocation, run the command:

```
trace-account all
```

The tool assumes the output of the anonymity revocation is placed in a file at `./regids.json`.
This can be changed to another path with the option `regids`.

### Single
In order to demo the tool with a single account without running anonymity revocation, one can run the command:

```
trace-account single --adress 4U9NrFTcHJRAC9SF4XrS1kACYE3GigMPo4W4QuwLnKyampMCnV
```

The option `address` should be a valid address for an account on chain. 
If additionally the option `decryption-key` contains the decryption key of that account, any encrypted amounts will be decrypted in the log.