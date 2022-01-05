# Transaction logger

Log affected accounts and smart contracts into a postgres database.

# Supported configuration options

- `TRANSACTION_LOGGER_NODES`
  List of nodes to query. They are used in order, and the next one is only used
  if the querying preceding one failed. Must be non-empty. For example
  `http://localhost:10000,http://localhost:13000`

- `TRANSACTION_LOGGER_RPC_TOKEN`
  GRPC access token for all the nodes.

- `TRANSACTION_LOGGER_DB_STRING`
  Database connection string for the postgres database.
  For example `host=localhost dbname=transaction-outcome user=postgres password=password port=5432`

- `TRANSACTION_LOGGER_LOG_LEVEL`
  Log level. One of `off`, `error`, `warn`, `info`, `debug`

- `TRANSACTION_LOGGER_NUM_PARALLEL_QUERIES`
  Maximum number of parallel queries to make to the node. Usually 1 is the
  correct number, but during initial catchup it is useful to increase this to,
  say 8 to take advantage of parallelism in queries which are typically IO bound.
