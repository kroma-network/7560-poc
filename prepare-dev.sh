GETH_DATA_DIR=./db

echo "
--datadir=$GETH_DATA_DIR
--dev
--dev.gaslimit=30000000
--http
--http.api='eth,net,web3,personal,debug'
--http.port=8545
--rpc.allow-unprotected-txs
--config=circleciconfig.toml
" | pbcopy
