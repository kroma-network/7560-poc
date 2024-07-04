package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	cmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"math/big"
	"strings"
)

const MaxContextSize = 65536

type ValidationPhaseResult struct {
	TxIndex                int
	Tx                     *types.Transaction
	TxHash                 common.Hash
	PaymasterContext       []byte
	NonceValidationUsedGas uint64
	DeploymentUsedGas      uint64
	ValidationUsedGas      uint64
	PmValidationUsedGas    uint64
	SenderValidAfter       uint64
	SenderValidUntil       uint64
	PmValidAfter           uint64
	PmValidUntil           uint64
	Payment                *common.Address
	PrepaidGas             *uint256.Int
}

// HandleRip7560Transactions apply state changes of all sequential RIP-7560 transactions and return
// the number of handled transactions
// the transactions array must start with the RIP-7560 transaction
func HandleRip7560Transactions(transactions []*types.Transaction, index int, statedb *state.StateDB, coinbase *common.Address, header *types.Header, gp *GasPool, chainConfig *params.ChainConfig, bc ChainContext, cfg vm.Config) ([]*types.Transaction, types.Receipts, []*types.Log, error) {
	validatedTransactions := make([]*types.Transaction, 0)
	receipts := make([]*types.Receipt, 0)
	allLogs := make([]*types.Log, 0)

	iTransactions, iReceipts, iLogs, err := handleRip7560Transactions(transactions, index, statedb, coinbase, header, gp, chainConfig, bc, cfg)
	if err != nil {
		log.Error("Failed to handleRip7560Transactions", "err", err)
		return nil, nil, nil, err
	}
	validatedTransactions = append(validatedTransactions, iTransactions...)
	receipts = append(receipts, iReceipts...)
	allLogs = append(allLogs, iLogs...)
	return validatedTransactions, receipts, allLogs, nil
}

func handleRip7560Transactions(transactions []*types.Transaction, index int, statedb *state.StateDB, coinbase *common.Address, header *types.Header, gp *GasPool, chainConfig *params.ChainConfig, bc ChainContext, cfg vm.Config) ([]*types.Transaction, types.Receipts, []*types.Log, error) {
	validationPhaseResults := make([]*ValidationPhaseResult, 0)
	validatedTransactions := make([]*types.Transaction, 0)
	var bundleHeaderTransaction *types.Transaction
	receipts := make([]*types.Receipt, 0)
	allLogs := make([]*types.Log, 0)

	// check bundle header transaction exists
	if transactions[0].Type() == types.Rip7560BundleHeaderType {
		bundleHeaderTransaction = transactions[0]
		transactions = transactions[1:]
	}

	for i, tx := range transactions[index:] {
		if tx.Type() != types.Rip7560Type {
			break
		}

		// No issues should occur during the validation phase.
		// However, in the unlikely event that something goes wrong,
		// we will revert to the previous state and invalidate the transaction.
		var (
			snapshot = statedb.Snapshot()
			prevGas  = gp.Gas()
		)

		statedb.SetTxContext(tx.Hash(), len(validatedTransactions))
		log.Info("[RIP-7560] Validation Phase - BuyGas", "i", i)
		payment, prepaidGas, err := BuyGasRip7560Transaction(chainConfig, gp, header, tx, statedb)
		if err != nil {
			log.Warn("[RIP-7560] Failed to BuyGasRip7560Transaction", "err", err)
			// TODO : do we have to drop bundle?
			continue
		}
		var vpr *ValidationPhaseResult
		log.Info("[RIP-7560] Validation Phase - Validation")
		signer := types.MakeSigner(chainConfig, header.Number, header.Time)
		signingHash := signer.Hash(tx)
		vpr, err = ApplyRip7560ValidationPhases(chainConfig, bc, coinbase, gp, statedb, header, tx, cfg, signingHash)
		if err != nil {
			log.Warn("[RIP-7560] Failed to ApplyRip7560ValidationPhases", "err", err)
			// If an error occurs in the validation phase, invalidate the transaction
			statedb.RevertToSnapshot(snapshot)
			gp.SetGas(prevGas)
			continue
		}
		statedb.IntermediateRoot(true)

		vpr.Payment = payment
		vpr.PrepaidGas = prepaidGas
		validationPhaseResults = append(validationPhaseResults, vpr)
		validatedTransactions = append(validatedTransactions, tx)
	}

	// This is the line separating the Validation and Execution phases
	// It should be separated to implement the mempool-friendly AA RIP (number not assigned yet)
	for i, vpr := range validationPhaseResults {
		// TODO: this will miss all validation phase events - pass in 'vpr'
		statedb.SetTxContext(vpr.Tx.Hash(), i)
		log.Info("[RIP-7560] Execution Phase", "i", i)
		executionResult, paymasterPostOpResult, cumulativeGasUsed, err := ApplyRip7560ExecutionPhase(chainConfig, vpr, bc, coinbase, gp, statedb, header, cfg, vpr.Payment, vpr.PrepaidGas)

		root := statedb.IntermediateRoot(true).Bytes()
		receipt := &types.Receipt{Type: vpr.Tx.Type(), PostState: root, CumulativeGasUsed: cumulativeGasUsed}

		// Set the receipt logs and create the bloom filter.
		receipt.Logs = statedb.GetLogs(vpr.Tx.Hash(), header.Number.Uint64(), header.Hash())

		if executionResult.Failed() || (paymasterPostOpResult != nil && paymasterPostOpResult.Failed()) {
			receipt.Status = types.ReceiptStatusFailed
		} else {
			receipt.Status = types.ReceiptStatusSuccessful
		}

		if err != nil {
			return nil, nil, nil, err
		}

		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}

	if bundleHeaderTransaction != nil {
		validatedTransactions = append([]*types.Transaction{bundleHeaderTransaction}, validatedTransactions...)
		receipt := &types.Receipt{
			Type:              types.Rip7560BundleHeaderType,
			Status:            types.ReceiptStatusSuccessful,
			CumulativeGasUsed: 0,
		}
		receipts = append([]*types.Receipt{receipt}, receipts...)
		allLogs = append(receipt.Logs, allLogs...)
	}

	return validatedTransactions, receipts, allLogs, nil
}

// BuyGasRip7560Transaction
// todo: move to a suitable interface, whatever that is
// todo 2: maybe handle the "shared gas pool" situation instead of just overriding it completely?
func BuyGasRip7560Transaction(chainConfig *params.ChainConfig, gp *GasPool, header *types.Header, tx *types.Transaction, state vm.StateDB) (*common.Address, *uint256.Int, error) {
	st := tx.Rip7560TransactionData()
	gasLimit := st.Gas + st.ValidationGas + st.PaymasterGas + st.PostOpGas + params.Tx7560BaseGas
	// Store prepaid values in gas units
	mggas := new(uint256.Int).SetUint64(gasLimit)
	// adjust effectiveGasPrice
	effectiveGasPrice := cmath.BigMin(new(big.Int).Add(st.GasTipCap, header.BaseFee), st.GasFeeCap)
	mgval := new(uint256.Int).Mul(mggas, new(uint256.Int).SetUint64(effectiveGasPrice.Uint64()))

	// calculate rollup cost
	var l1Cost *big.Int
	L1CostFunc := types.NewL1CostFunc(chainConfig, state)
	if L1CostFunc != nil {
		l1Cost = L1CostFunc(tx.RollupCostData(), header.Time)
	}
	mgval = mgval.Add(mgval, new(uint256.Int).SetUint64(l1Cost.Uint64()))
	balanceCheck := new(uint256.Int).Set(mgval)

	chargeFrom := *st.Sender
	if len(st.PaymasterData) >= 20 {
		chargeFrom = [20]byte(st.PaymasterData[:20])
	}

	if have, want := state.GetBalance(chargeFrom), balanceCheck; have.Cmp(want) < 0 {
		return &common.Address{}, new(uint256.Int), fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, chargeFrom.Hex(), have, want)
	}

	state.SubBalance(chargeFrom, mgval)
	err := gp.SubGas(mggas.Uint64())
	if err != nil {
		return &common.Address{}, new(uint256.Int), err
	}
	return &chargeFrom, mggas, nil
}

func ApplyRip7560ValidationPhases(chainConfig *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, cfg vm.Config, signingHash common.Hash) (*ValidationPhaseResult, error) {
	blockContext := NewEVMBlockContext(header, bc, author, chainConfig, statedb)
	txContext := vm.TxContext{
		Origin:   *tx.Rip7560TransactionData().Sender,
		GasPrice: tx.GasFeeCap(),
	}
	evm := vm.NewEVM(blockContext, txContext, statedb, chainConfig, cfg)

	/*** Nonce Validation Frame ***/
	nonceValidationMsg := prepareNonceValidationMessage(tx, chainConfig)
	var nonceValidationUsedGas uint64
	if nonceValidationMsg != nil {
		log.Info("[RIP-7560] Nonce Validation Frame", "nonceType", "2D-nonce")
		resultNonceManager, err := ApplyMessage(evm, nonceValidationMsg, gp)
		if err != nil {
			log.Error("[RIP-7560] Nonce Validation Frame", "ApplyMessage.Err", err)
			return nil, err
		}
		if resultNonceManager.Err != nil {
			log.Error("[RIP-7560] Nonce Validation Frame", "resultNonceManager.Err", resultNonceManager.Err)
			return nil, resultNonceManager.Err
		}
		nonceValidationUsedGas = resultNonceManager.UsedGas
	} else {
		log.Info("[RIP-7560] Nonce Validation Frame", "nonceType", "legacy-nonce")
		// Use legacy nonce validation
		stNonce := statedb.GetNonce(*tx.Rip7560TransactionData().Sender)
		// TODO(sm-stack): add error messages like ErrNonceTooLow, ErrNonceTooHigh, etc.
		if msgNonce := tx.Rip7560TransactionData().BigNonce.Uint64(); stNonce != msgNonce {
			return nil, errors.New("nonce validation failed - invalid transaction")
		} else if stNonce == 0 {
			deployerData := tx.Rip7560TransactionData().DeployerData
			if len(deployerData) < 20 {
				return nil, errors.New("nonce validation failed - invalid transaction")
			}
			if bytes.Equal(deployerData[:20], common.Address{}.Bytes()) {
				return nil, errors.New("nonce validation failed - invalid transaction")
			}
		} else {
			statedb.SetNonce(txContext.Origin, stNonce+1)
		}
	}

	/*** Deployer Frame ***/
	deployerMsg := prepareDeployerMessage(tx, chainConfig, nonceValidationUsedGas)
	var deploymentUsedGas uint64
	if deployerMsg != nil {
		resultDeployer, err := ApplyMessage(evm, deployerMsg, gp)
		if err != nil {
			log.Error("[RIP-7560] Deployer Frame", "ApplyMessage.Err", err)
			return nil, err
		}
		deployedAddr := common.BytesToAddress(resultDeployer.ReturnData)
		if resultDeployer.Failed() || statedb.GetCode(deployedAddr) == nil {
			// TODO: bubble up the inner error message to the user, if possible
			return nil, errors.New("account deployment failed - invalid transaction")
		} else if deployedAddr != *tx.Rip7560TransactionData().Sender {
			return nil, errors.New("deployed address mismatch - invalid transaction")
		}
		// TODO : would be handled inside IntrinsicGas
		deploymentUsedGas = resultDeployer.UsedGas + params.TxGasContractCreation
	}

	/*** Account Validation Frame ***/
	accountValidationMsg, err := prepareAccountValidationMessage(tx, chainConfig, signingHash, nonceValidationUsedGas, deploymentUsedGas)
	resultAccountValidation, err := ApplyMessage(evm, accountValidationMsg, gp)
	if err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "ApplyMessage.Err", err)
		return nil, err
	}
	if resultAccountValidation.Err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "resultAccountValidation.Err", resultAccountValidation.Err)
		return nil, resultAccountValidation.Err
	}
	validAfter, validUntil, err := validateAccountReturnData(resultAccountValidation.ReturnData)
	if err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "validateAccountReturnData.Err", err)
		return nil, err
	}
	err = validateValidityTimeRange(header.Time, validAfter, validUntil)
	if err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "validateValidityTimeRange.Err", err)
		return nil, err
	}

	/*** Paymaster Validation Frame ***/
	paymasterContext, pmValidationUsedGas, pmValidAfter, pmValidUntil, err := applyPaymasterValidationFrame(tx, chainConfig, signingHash, evm, gp, statedb, header)
	if err != nil {
		log.Error("[RIP-7560] Paymaster Validation Frame", "err", err)
	}
	vpr := &ValidationPhaseResult{
		Tx:                     tx,
		TxHash:                 tx.Hash(),
		PaymasterContext:       paymasterContext,
		NonceValidationUsedGas: nonceValidationUsedGas,
		DeploymentUsedGas:      deploymentUsedGas,
		ValidationUsedGas:      resultAccountValidation.UsedGas + params.Tx7560BaseGas,
		PmValidationUsedGas:    pmValidationUsedGas,
		SenderValidAfter:       validAfter,
		SenderValidUntil:       validUntil,
		PmValidAfter:           pmValidAfter,
		PmValidUntil:           pmValidUntil,
	}
	log.Info("[RIP-7560] ValidationPhaseResult", "vpr", vpr)

	return vpr, nil
}

func applyPaymasterValidationFrame(tx *types.Transaction, chainConfig *params.ChainConfig, signingHash common.Hash, evm *vm.EVM, gp *GasPool, statedb *state.StateDB, header *types.Header) ([]byte, uint64, uint64, uint64, error) {
	var pmValidationUsedGas uint64
	var paymasterContext []byte
	var pmValidAfter uint64
	var pmValidUntil uint64
	paymasterMsg, err := preparePaymasterValidationMessage(tx, chainConfig, signingHash)
	if err != nil {
		log.Error("[RIP-7560] Paymaster Validation Frame", "preparePaymasterValidationMessage.err", err)
		return nil, 0, 0, 0, err

	}
	if paymasterMsg != nil {
		resultPm, err := ApplyMessage(evm, paymasterMsg, gp)
		if err != nil {
			log.Error("[RIP-7560] Paymaster Validation Frame", "ApplyMessage.err", err)
			return nil, 0, 0, 0, err
		}
		statedb.IntermediateRoot(true)
		if resultPm.Failed() {
			return nil, 0, 0, 0, errors.New("paymaster validation failed - invalid transaction")
		}
		pmValidationUsedGas = resultPm.UsedGas
		paymasterContext, pmValidAfter, pmValidUntil, err = validatePaymasterReturnData(resultPm.ReturnData)
		if err != nil {
			log.Error("[RIP-7560] Paymaster Validation Frame", "validatePaymasterReturnData.err", err)
			return nil, 0, 0, 0, err
		}
		err = validateValidityTimeRange(header.Time, pmValidAfter, pmValidUntil)
		if err != nil {
			log.Error("[RIP-7560] Paymaster Validation Frame", "validateValidityTimeRange.err", err)
			return nil, 0, 0, 0, err
		}
	}
	return paymasterContext, pmValidationUsedGas, pmValidAfter, pmValidUntil, nil
}

func applyPaymasterPostOpFrame(vpr *ValidationPhaseResult, executionResult *ExecutionResult, evm *vm.EVM, gp *GasPool) (*ExecutionResult, error) {
	var paymasterPostOpResult *ExecutionResult
	paymasterPostOpMsg, err := preparePostOpMessage(vpr, evm.ChainConfig(), executionResult)
	if err != nil {
		return nil, err
	}
	paymasterPostOpResult, err = ApplyMessage(evm, paymasterPostOpMsg, gp)
	if err != nil {
		return nil, err
	}
	// TODO: revert the execution phase changes
	return paymasterPostOpResult, nil
}

func ApplyRip7560ExecutionPhase(config *params.ChainConfig, vpr *ValidationPhaseResult, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, cfg vm.Config, payment *common.Address, prepaidGas *uint256.Int) (*ExecutionResult, *ExecutionResult, uint64, error) {
	// revert back here if postOp fails
	var snapshot = statedb.Snapshot()
	blockContext := NewEVMBlockContext(header, bc, author, config, statedb)
	message, err := TransactionToMessage(vpr.Tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	txContext := NewEVMTxContext(message)
	txContext.Origin = *vpr.Tx.Rip7560TransactionData().Sender
	evm := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	accountExecutionMsg := prepareAccountExecutionMessage(vpr.Tx, evm.ChainConfig())
	executionResult, err := ApplyMessage(evm, accountExecutionMsg, gp)
	if err != nil {
		log.Error("[RIP-7560] Execution Frame", "ApplyMessage.Err", err)
		return nil, nil, 0, err
	}
	log.Info("[RIP-7560] Execution gas info", "executionResult.UsedGas", executionResult.UsedGas)

	var paymasterPostOpResult *ExecutionResult
	if len(vpr.PaymasterContext) != 0 {
		paymasterPostOpResult, err = applyPaymasterPostOpFrame(vpr, executionResult, evm, gp)
		if err != nil {
			log.Error("[RIP-7560] Post-transaction Frame", "applyPaymasterPostOpFrame.err", err)
			return nil, nil, 0, err
		}
		// revert the execution phase changes
		if paymasterPostOpResult.Failed() {
			log.Warn("[RIP-7560] Post-transaction Frame - reverted", "paymasterPostOpResult", paymasterPostOpResult)
			statedb.RevertToSnapshot(snapshot)
		}
	}

	cumulativeGasUsed :=
		vpr.NonceValidationUsedGas +
			vpr.ValidationUsedGas +
			vpr.DeploymentUsedGas +
			vpr.PmValidationUsedGas +
			executionResult.UsedGas
	if paymasterPostOpResult != nil {
		cumulativeGasUsed +=
			paymasterPostOpResult.UsedGas
		log.Info("[RIP-7560] Execution gas info", "paymasterPostOpResult.UsedGas", paymasterPostOpResult.UsedGas)
	}

	// calculation for intrinsicGas
	// TODO: integrated with code in state_transition
	rules := evm.ChainConfig().Rules(evm.Context.BlockNumber, evm.Context.Random != nil, evm.Context.Time)
	intrGas, err := IntrinsicGasWithOption(vpr.Tx.Data(), vpr.Tx.AccessList(), false, rules.IsHomestead, rules.IsIstanbul, rules.IsShanghai, true, false)
	if err != nil {
		return nil, nil, 0, err
	}
	cumulativeGasUsed += intrGas
	log.Info("[RIP-7560] Execution gas info", "intrGas", intrGas)

	// apply a penalty && refund gas
	// TODO: If this value is not persistent, it should be modified to be managed on-chain config
	const UNUSED_GAS_PENALTY_PERCENT = 10
	gasPenalty := (prepaidGas.Uint64() - cumulativeGasUsed) * UNUSED_GAS_PENALTY_PERCENT / 100
	cumulativeGasUsed += gasPenalty
	statedb.AddBalance(*payment, uint256.NewInt((prepaidGas.Uint64()-cumulativeGasUsed)*evm.Context.BaseFee.Uint64()))
	gp.AddGas(prepaidGas.Uint64() - cumulativeGasUsed)
	log.Info("[RIP-7560] Execution gas info", "gasPenalty", gasPenalty)

	// payments for rollup gas expenses to recipients
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(cumulativeGasUsed), evm.Context.BaseFee)
	amtU256, overflow := uint256.FromBig(gasCost)
	if overflow {
		return nil, nil, 0, fmt.Errorf("optimism gas cost overflows U256: %d", gasCost)
	}
	log.Info("[RIP-7560] Execution gas info", "BaseFee", amtU256)
	statedb.AddBalance(params.OptimismBaseFeeRecipient, amtU256)
	if l1Cost := evm.Context.L1CostFunc(vpr.Tx.RollupCostData(), evm.Context.Time); l1Cost != nil {
		amtU256, overflow = uint256.FromBig(l1Cost)
		if overflow {
			return nil, nil, 0, fmt.Errorf("optimism l1 cost overflows U256: %d", l1Cost)
		}
		statedb.AddBalance(params.OptimismL1FeeRecipient, amtU256)
		log.Info("[RIP-7560] Execution gas info", "L1Fee", amtU256)
	}

	return executionResult, paymasterPostOpResult, cumulativeGasUsed, nil
}

func prepareNonceValidationMessage(baseTx *types.Transaction, chainConfig *params.ChainConfig) *Message {
	tx := baseTx.Rip7560TransactionData()

	// TODO(sm-stack): add error handling for bigNonce value over 32 bytes
	key := make([]byte, 32)
	fromBig, _ := uint256.FromBig(tx.BigNonce)
	fromBig.WriteToSlice(key)

	// Use legacy nonce validation if the key is all zeros
	if bytes.Equal(key[:24], make([]byte, 24)) {
		return nil
	}

	nonceValidationData := make([]byte, 0)
	nonceValidationData = append(nonceValidationData[:], tx.Sender.Bytes()...)
	nonceValidationData = append(nonceValidationData[:], key...)

	return &Message{
		From:              chainConfig.EntryPointAddress,
		To:                &chainConfig.NonceManagerAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              nonceValidationData,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsRip7560Frame:    true,
	}
}

func prepareDeployerMessage(baseTx *types.Transaction, config *params.ChainConfig, nonceValidationUsedGas uint64) *Message {
	tx := baseTx.Rip7560TransactionData()
	if len(tx.DeployerData) < 20 {
		return nil
	}
	var deployerAddress common.Address = [20]byte(tx.DeployerData[0:20])
	return &Message{
		From:              config.DeployerCallerAddress,
		To:                &deployerAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas - nonceValidationUsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              tx.DeployerData[20:],
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsRip7560Frame:    true,
	}
}

func prepareAccountValidationMessage(baseTx *types.Transaction, chainConfig *params.ChainConfig, signingHash common.Hash, nonceValidationUsedGas, deploymentUsedGas uint64) (*Message, error) {
	tx := baseTx.Rip7560TransactionData()
	jsondata := `[
	{"type":"function","name":"validateTransaction","inputs": [{"name": "version","type": "uint256"},{"name": "txHash","type": "bytes32"},{"name": "transaction","type": "bytes"}]}
	]`

	validateTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		return nil, err
	}
	txAbiEncoding, err := tx.AbiEncode()
	validateTransactionData, err := validateTransactionAbi.Pack("validateTransaction", big.NewInt(1), signingHash, txAbiEncoding)
	return &Message{
		From:              chainConfig.EntryPointAddress,
		To:                tx.Sender,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas - nonceValidationUsedGas - deploymentUsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              validateTransactionData,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsRip7560Frame:    true,
	}, nil
}

func preparePaymasterValidationMessage(baseTx *types.Transaction, config *params.ChainConfig, signingHash common.Hash) (*Message, error) {
	tx := baseTx.Rip7560TransactionData()
	if len(tx.PaymasterData) < 20 {
		return nil, nil
	}
	var paymasterAddress common.Address = [20]byte(tx.PaymasterData[0:20])
	jsondata := `[
		{"type":"function","name":"validatePaymasterTransaction","inputs": [{"name": "version","type": "uint256"},{"name": "txHash","type": "bytes32"},{"name": "transaction","type": "bytes"}]}
	]`

	validateTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	txAbiEncoding, err := tx.AbiEncode()
	data, err := validateTransactionAbi.Pack("validatePaymasterTransaction", big.NewInt(1), signingHash, txAbiEncoding)

	if err != nil {
		return nil, err
	}
	return &Message{
		From:              config.EntryPointAddress,
		To:                &paymasterAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.PaymasterGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              data,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsRip7560Frame:    true,
	}, nil
}

func prepareAccountExecutionMessage(baseTx *types.Transaction, config *params.ChainConfig) *Message {
	tx := baseTx.Rip7560TransactionData()
	return &Message{
		From:              config.EntryPointAddress,
		To:                tx.Sender,
		Value:             big.NewInt(0),
		GasLimit:          tx.Gas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              tx.Data,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsRip7560Frame:    true,
	}
}

func preparePostOpMessage(vpr *ValidationPhaseResult, chainConfig *params.ChainConfig, executionResult *ExecutionResult) (*Message, error) {
	if len(vpr.PaymasterContext) == 0 {
		return nil, nil
	}

	tx := vpr.Tx.Rip7560TransactionData()
	jsondata := `[
		{"type":"function","name":"postPaymasterTransaction","inputs": [{"name": "success","type": "bool"},{"name": "actualGasCost","type": "uint256"},{"name": "context","type": "bytes"}]}
	]`
	postPaymasterTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		return nil, err
	}
	postOpData, err := postPaymasterTransactionAbi.Pack("postPaymasterTransaction", true, big.NewInt(0), vpr.PaymasterContext)
	if err != nil {
		return nil, err
	}
	var paymasterAddress common.Address = [20]byte(tx.PaymasterData[0:20])
	return &Message{
		From:              chainConfig.EntryPointAddress,
		To:                &paymasterAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.PaymasterGas - executionResult.UsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              postOpData,
		AccessList:        tx.AccessList,
		SkipAccountChecks: true,
		IsRip7560Frame:    true,
	}, nil
}

func validateAccountReturnData(data []byte) (uint64, uint64, error) {
	var MAGIC_VALUE_SENDER = [20]byte{0xbf, 0x45, 0xc1, 0x66}
	if len(data) != 32 {
		return 0, 0, errors.New("invalid account return data length")
	}
	magicExpected := common.Bytes2Hex(data[:20])
	if magicExpected != common.Bytes2Hex(MAGIC_VALUE_SENDER[:]) {
		return 0, 0, errors.New("account did not return correct MAGIC_VALUE")
	}
	validUntil := binary.BigEndian.Uint64(data[4:12])
	validAfter := binary.BigEndian.Uint64(data[12:20])
	return validAfter, validUntil, nil
}

func validatePaymasterReturnData(data []byte) ([]byte, uint64, uint64, error) {
	var MAGIC_VALUE_PAYMASTER = [20]byte{0xe0, 0xe6, 0x18, 0x3a}
	jsondata := `[
		{"type": "function","name": "validatePaymasterTransaction","outputs": [{"name": "validationData","type": "bytes32"},{"name": "context","type": "bytes"}]}
	]`
	validatePaymasterTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		// todo: wrap error message
		return nil, 0, 0, err
	}

	var validatePaymasterResult struct {
		ValidationData [32]byte
		Context        []byte
	}

	err = validatePaymasterTransactionAbi.UnpackIntoInterface(&validatePaymasterResult, "validatePaymasterTransaction", data)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(validatePaymasterResult.Context) > MaxContextSize {
		return nil, 0, 0, errors.New("paymaster returned context size too large")
	}
	magicExpected := common.Bytes2Hex(validatePaymasterResult.ValidationData[:20])
	if magicExpected != common.Bytes2Hex(MAGIC_VALUE_PAYMASTER[:]) {
		return nil, 0, 0, errors.New("paymaster did not return correct MAGIC_VALUE")
	}
	validUntil := binary.BigEndian.Uint64(validatePaymasterResult.ValidationData[4:12])
	validAfter := binary.BigEndian.Uint64(validatePaymasterResult.ValidationData[12:20])
	context := validatePaymasterResult.Context

	return context, validAfter, validUntil, nil
}

func validateValidityTimeRange(time uint64, validAfter uint64, validUntil uint64) error {
	if validUntil == 0 && validAfter == 0 {
		return nil
	}
	if validUntil < validAfter {
		return errors.New("RIP-7560 transaction validity range invalid")
	}
	if time > validUntil {
		return errors.New("RIP-7560 transaction validity expired")
	}
	if time < validAfter {
		return errors.New("RIP-7560 transaction validity not reached yet")
	}
	return nil
}
