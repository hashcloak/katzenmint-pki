# Basic ABCI app

## Instructions

1. [Install tendermint v0.34.6](https://docs.tendermint.com/master/introduction/install.html)
2. `TMHOME=`pwd`/chain tendermint init`
3. `go build`
4. `./katzenmint_abci_app -config ./chain/config/config.toml`
5. `curl -s 'localhost:26657/broadcast_tx_commit?tx="tendermint=rocks"'`
6. `curl -s 'localhost:26657/abci_query?data="tendermint"'`
