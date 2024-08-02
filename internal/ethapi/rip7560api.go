package ethapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/gasestimator"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"
	"math"
	"math/big"
	"time"
)

type Rip7560UsedGas struct {
	ValidationGas hexutil.Uint64 `json:"validationGas"`
	ExecutionGas  hexutil.Uint64 `json:"executionGas"`
}

func (s *TransactionAPI) SendRip7560TransactionsBundle(ctx context.Context, args []TransactionArgs, creationBlock *big.Int, expectedRevenue *big.Int, bundlerId string) (common.Hash, error) {
	if len(args) == 0 {
		return common.Hash{}, errors.New("submitted bundle has zero length")
	}
	log.Info("[RIP-7560] SendRip7560TransactionsBundle", "bundlerId", bundlerId)
	txs := make([]*types.Transaction, len(args))
	for i := 0; i < len(args); i++ {
		txs[i] = args[i].toTransaction()
	}
	bundle := &types.ExternallyReceivedBundle{
		BundlerId:       bundlerId,
		ExpectedRevenue: expectedRevenue,
		ValidForBlock:   creationBlock,
		Transactions:    txs,
	}
	bundleHash := calculateBundleHash(txs)
	bundle.BundleHash = bundleHash
	err := SubmitRip7560Bundle(ctx, s.b, bundle)
	if err != nil {
		return common.Hash{}, err
	}
	return bundleHash, nil
}

func (s *TransactionAPI) GetRip7560BundleStatus(ctx context.Context, hash common.Hash) (*types.BundleReceipt, error) {
	bundleStats, err := s.b.GetRip7560BundleStatus(ctx, hash)
	return bundleStats, err
}

func (s *TransactionAPI) CallRip7560Validation(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *StateOverride, blockOverrides *BlockOverrides) (*core.ValidationPhaseResult, error) {
	if blockNrOrHash == nil {
		latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
		blockNrOrHash = &latest
	}

	// TODO(sm-stack): Configure RIP-7560 enabled devnet option
	//header, err := headerByNumberOrHash(ctx, s.b, *blockNrOrHash)
	//if err != nil {
	//	return nil, err
	//}

	//if s.b.ChainConfig().IsRIP7560(header.Number) {
	//	return nil, fmt.Errorf("cannot call RIP-7560 validation on pre-rip7560 block %v", header.Number)
	//}

	result, err := DoCallRip7560Validation(ctx, s.b, args, *blockNrOrHash, overrides, blockOverrides, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
	if err != nil {
		return nil, err
	}
	// just return the result and err
	return result, nil
}

// SubmitRip7560Bundle is a helper function that submits a bundle of Type 4 transactions to txPool and logs a message.
func SubmitRip7560Bundle(ctx context.Context, b Backend, bundle *types.ExternallyReceivedBundle) error {
	return b.SubmitRip7560Bundle(bundle)
}

func doCallRip7560Validation(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, overrides *StateOverride, blockOverrides *BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ValidationPhaseResult, error) {
	if err := overrides.Apply(state); err != nil {
		return nil, err
	}
	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	tx := args.toTransaction()

	chainConfig := b.ChainConfig()
	bc := NewChainContext(ctx, b)
	blockContext := core.NewEVMBlockContext(header, bc, &header.Coinbase, chainConfig, state)
	if blockOverrides != nil {
		blockOverrides.Apply(&blockContext)
	}
	txContext := vm.TxContext{
		Origin:   *tx.Rip7560TransactionData().Sender,
		GasPrice: tx.GasPrice(),
	}
	evm := vm.NewEVM(blockContext, txContext, state, chainConfig, vm.Config{NoBaseFee: true})

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the validation phase.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	err := core.BuyGasRip7560Transaction(chainConfig, gp, header, tx, state)
	if err != nil {
		return nil, err
	}

	result, err := core.ApplyRip7560ValidationPhases(chainConfig, bc, &header.Coinbase, gp, state, header, tx, evm.Config)
	if err := state.Error(); err != nil {
		return nil, err
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("validation aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, tx.Rip7560TransactionData().ValidationGas)
	}
	return result, nil
}

func DoCallRip7560Validation(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride, blockOverrides *BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ValidationPhaseResult, error) {
	defer func(start time.Time) {
		log.Debug("Executing RIP7560 validation finished", "runtime", time.Since(start))
	}(time.Now())

	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	return doCallRip7560Validation(ctx, b, args, state, header, overrides, blockOverrides, timeout, globalGasCap)
}

func DoEstimateRip7560TransactionGas(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride, gasCap uint64) (*Rip7560UsedGas, error) {
	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err = overrides.Apply(state); err != nil {
		return nil, err
	}
	// Construct the gas estimator option from the user input
	chainConfig := b.ChainConfig()
	bc := NewChainContext(ctx, b)
	tx := args.toTransaction()

	gp := new(core.GasPool).AddGas(math.MaxUint64)
	err = core.BuyGasRip7560Transaction(chainConfig, gp, header, tx, state)
	if err != nil {
		return nil, err
	}
	opts := &gasestimator.Options{
		Config:     chainConfig,
		Chain:      bc,
		Header:     header,
		State:      state,
		ErrorRatio: estimateGasErrorRatio,
	}

	vg, err := gasestimator.EstimateRip7560Validation(ctx, tx, opts, gasCap)
	if err != nil {
		return nil, err
	}

	eg, _, err := gasestimator.EstimateRip7560Execution(ctx, opts, gasCap)
	if err != nil {
		return nil, err
	}

	return &Rip7560UsedGas{
		ValidationGas: hexutil.Uint64(vg),
		ExecutionGas:  hexutil.Uint64(eg),
	}, nil
}

func (s *BlockChainAPI) EstimateRip7560TransactionGas(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *StateOverride) (*Rip7560UsedGas, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}

	// TODO(sm-stack): Configure RIP-7560 enabled devnet option
	//header, err := headerByNumberOrHash(ctx, s.b, bNrOrHash)
	//if err != nil {
	//	return 0, err
	//}

	//if s.b.ChainConfig().IsRIP7560(header.Number) {
	//	return 0, fmt.Errorf("cannot estimate gas for RIP-7560 tx on pre-bedrock block %v", header.Number)
	//}

	return DoEstimateRip7560TransactionGas(ctx, s.b, args, bNrOrHash, overrides, s.b.RPCGasCap())
}

// TODO: If this code is indeed necessary, keep it in utils; better - remove altogether.
func calculateBundleHash(txs []*types.Transaction) common.Hash {
	appendedTxIds := make([]byte, 0)
	for _, tx := range txs {
		txHash := tx.Hash()
		appendedTxIds = append(appendedTxIds, txHash[:]...)
	}

	return rlpHash(appendedTxIds)
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}
