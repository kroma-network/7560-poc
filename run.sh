VERBOSITY=${GETH_VERBOSITY:-3}
GETH_DATA_DIR=./db
GETH_CHAINDATA_DIR="$GETH_DATA_DIR/geth/chaindata"
GENESIS_FILE_PATH="${GENESIS_FILE_PATH:-../.devnet/genesis-l2.json}"
CHAIN_ID=$(cat "$GENESIS_FILE_PATH" | jq -r .config.chainId)
RPC_PORT="${RPC_PORT:-38545}"
WS_PORT="${WS_PORT:-38546}"

if [ ! -d "$GETH_CHAINDATA_DIR" ]; then
	echo "$GETH_CHAINDATA_DIR missing, running init"
	echo "Initializing genesis."
	./build/bin/geth --verbosity="$VERBOSITY" init \
		--datadir="$GETH_DATA_DIR" \
		"$GENESIS_FILE_PATH"
else
	echo "$GETH_CHAINDATA_DIR exists."
fi

./build/bin/geth \
  --datadir ./db \
  --http \
  --http.corsdomain="*" \
  --http.vhosts="*" \
  --http.addr=0.0.0.0 \
  --http.port=38545 \
  --http.api=web3,debug,eth,txpool,net,engine \
  --ws \
  --ws.addr=0.0.0.0 \
  --ws.port=38546 \
  --ws.origins="*" \
  --ws.api=debug,eth,txpool,net,engine \
  --syncmode=full \
  --gcmode=archive \
  --nodiscover \
  --maxpeers=0 \
  --networkid=901 \
  --authrpc.vhosts="*" \
  --authrpc.addr=0.0.0.0 \
  --authrpc.port=38551 \
  --authrpc.jwtsecret=./config/test-jwt-secret.txt \
  --rollup.disabletxpoolgossip=true \
  --metrics \
  --metrics.addr=0.0.0.0 \
  --metrics.port=36060 \
  --miner.recommit=1s \
  --override.canyon=0 \
  --override.ecotone=1721026803 \
  --override.fjord=1721026805 \
  --log.maxsize=100 \
  --log.rotate \
  --log.format=logfmt \
  --log.file=./runlog/geth.log \
  --log.maxbackups=100 \
