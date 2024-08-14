package core

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"math/big"
	"strings"
)

const MAGIC_VALUE_SENDER = uint64(0xbf45c166)
const MAGIC_VALUE_PAYMASTER = uint64(0xe0e6183a)
const MAGIC_VALUE_SIGFAIL = uint64(0x31665494)
const PAYMASTER_MAX_CONTEXT_SIZE = 65536

func PackValidationData(authorizerMagic uint64, validUntil, validAfter uint64) []byte {
	t := new(big.Int).SetUint64(uint64(validAfter))
	t = t.Lsh(t, 48).Add(t, new(big.Int).SetUint64(validUntil&0xffffff))
	t = t.Lsh(t, 160).Add(t, new(big.Int).SetUint64(uint64(authorizerMagic)))
	return common.LeftPadBytes(t.Bytes(), 32)
}

func UnpackValidationData(validationData []byte) (uint64, uint64, uint64) {
	validAfter := new(big.Int).SetBytes(validationData[:6]).Uint64()
	validUntil := new(big.Int).SetBytes(validationData[6:12]).Uint64()
	authorizerMagic := new(big.Int).SetBytes(validationData[12:32]).Uint64()
	return authorizerMagic, validUntil, validAfter
}

func UnpackPaymasterValidationReturn(paymasterValidationReturn []byte) ([]byte, []byte, error) {
	if len(paymasterValidationReturn) < 96 {
		return nil, nil, errors.New("paymaster return data: too short")
	}
	validationData := paymasterValidationReturn[0:32]
	//2nd bytes32 is ignored (its an offset value)
	contextLen := new(big.Int).SetBytes(paymasterValidationReturn[64:96])
	if uint64(len(paymasterValidationReturn)) < 96+contextLen.Uint64() {
		return nil, nil, errors.New("paymaster return data: unable to decode context")
	}
	if contextLen.Cmp(big.NewInt(PAYMASTER_MAX_CONTEXT_SIZE)) > 0 {
		return nil, nil, errors.New("paymaster return data: context too large")
	}

	context := paymasterValidationReturn[96 : 96+contextLen.Uint64()]
	return validationData, context, nil
}

type ValidationPhaseResult struct {
	TxIndex                int
	Tx                     *types.Transaction
	TxHash                 common.Hash
	PaymasterContext       []byte
	PreCharge              *uint256.Int
	EffectiveGasPrice      *uint256.Int
	NonceValidationUsedGas uint64
	DeploymentUsedGas      uint64
	ValidationUsedGas      uint64
	PmValidationUsedGas    uint64
	SenderValidAfter       uint64
	SenderValidUntil       uint64
	PmValidAfter           uint64
	PmValidUntil           uint64
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
	receipts := make([]*types.Receipt, 0)
	allLogs := make([]*types.Log, 0)

	// check bundle header transaction exists
	var bundleHeaderTransaction *types.Transaction
	if transactions[0].Type() == types.Rip7560BundleHeaderType {
		bundleHeaderTransaction = transactions[0]
		transactions = transactions[1:]
	}

	for _, tx := range transactions[index:] {
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

		statedb.SetTxContext(tx.Hash(), index+len(validatedTransactions))
		var vpr *ValidationPhaseResult
		vpr, err := ApplyRip7560ValidationPhases(chainConfig, bc, coinbase, gp, statedb, header, tx, cfg)
		if err != nil {
			// If an error occurs in the validation phase, invalidate the transaction
			statedb.RevertToSnapshot(snapshot)
			gp.SetGas(prevGas)
			continue
		}
		statedb.IntermediateRoot(true)

		validationPhaseResults = append(validationPhaseResults, vpr)
		validatedTransactions = append(validatedTransactions, tx)
	}

	// This is the line separating the Validation and Execution phases
	for i, vpr := range validationPhaseResults {
		// TODO: this will miss all validation phase events - pass in 'vpr'
		statedb.SetTxContext(vpr.Tx.Hash(), index+i)
		executionResult, paymasterPostOpResult, gasUsed, err := ApplyRip7560ExecutionPhase(chainConfig, vpr, bc, coinbase, gp, statedb, header, cfg)

		root := statedb.IntermediateRoot(true).Bytes()
		// TODO: reflect the real value of cumulative gas
		receipt := &types.Receipt{Type: vpr.Tx.Type(), PostState: root, TxHash: vpr.Tx.Hash(), GasUsed: gasUsed, CumulativeGasUsed: gasUsed}

		// Set the receipt logs and create the bloom filter.
		receipt.Logs = statedb.GetLogs(vpr.Tx.Hash(), header.Number.Uint64(), header.Hash())
		receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
		// TODO: consider way to add blocknumber and blockhash to receipt
		receipt.TransactionIndex = uint(vpr.TxIndex)

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
func BuyGasRip7560Transaction(chainConfig *params.ChainConfig, gp *GasPool, header *types.Header, tx *types.Transaction, state vm.StateDB, gasPrice *uint256.Int) (*uint256.Int, error) {
	st := tx.Rip7560TransactionData()
	gasLimit := st.Gas + st.ValidationGas + st.PaymasterGas + st.PostOpGas + params.Tx7560BaseGas
	// Store prepaid values in gas units
	preCharge := new(uint256.Int).SetUint64(gasLimit)
	preCharge = preCharge.Mul(preCharge, gasPrice)

	// calculate rollup cost
	var l1Cost *big.Int
	L1CostFunc := types.NewL1CostFunc(chainConfig, state)
	if L1CostFunc != nil {
		l1Cost = L1CostFunc(tx.RollupCostData(), header.Time)
		preCharge = preCharge.Add(preCharge, new(uint256.Int).SetUint64(l1Cost.Uint64()))
	}

	balanceCheck := new(uint256.Int).Set(preCharge)

	chargeFrom := *st.Sender
	if st.Paymaster != nil && st.Paymaster.Cmp(common.Address{}) != 0 {
		chargeFrom = *st.Paymaster
	}

	if have, want := state.GetBalance(chargeFrom), balanceCheck; have.Cmp(want) < 0 {
		return nil, fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, chargeFrom.Hex(), have, want)
	}

	state.SubBalance(chargeFrom, preCharge)
	err := gp.SubGas(preCharge.Uint64())
	if err != nil {
		return nil, err
	}
	return preCharge, nil
}

// refund the transaction payer (either account or paymaster) with the excess gas cost
func refundPayer(vpr *ValidationPhaseResult, state vm.StateDB, gasUsed uint64, gp *GasPool) {
	var chargeFrom *common.Address
	if vpr.PmValidationUsedGas == 0 {
		chargeFrom = vpr.Tx.Rip7560TransactionData().Sender
	} else {
		chargeFrom = vpr.Tx.Rip7560TransactionData().Paymaster
	}

	actualGasCost := new(uint256.Int).Mul(vpr.EffectiveGasPrice, new(uint256.Int).SetUint64(gasUsed))

	refund := new(uint256.Int).Sub(vpr.PreCharge, actualGasCost)

	state.AddBalance(*chargeFrom, refund)

	gp.AddGas(refund.Uint64())
}

// CheckNonceRip7560 prechecks nonce of transaction.
// (standard preCheck function check both nonce and no-code of account)
func CheckNonceRip7560(tx *types.Rip7560AccountAbstractionTx, st *state.StateDB) error {
	// Make sure this transaction's nonce is correct.
	stNonce := st.GetNonce(*tx.Sender)
	if msgNonce := tx.BigNonce.Uint64(); stNonce < msgNonce {
		return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh,
			tx.Sender.Hex(), msgNonce, stNonce)
	} else if stNonce > msgNonce {
		return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooLow,
			tx.Sender.Hex(), msgNonce, stNonce)
	} else if stNonce+1 < stNonce {
		return fmt.Errorf("%w: address %v, nonce: %d", ErrNonceMax,
			tx.Sender.Hex(), stNonce)
	}
	return nil
}

func ApplyRip7560ValidationPhases(chainConfig *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, cfg vm.Config, estimate ...bool) (*ValidationPhaseResult, error) {
	var estimateFlag = false
	if len(estimate) > 0 && estimate[0] {
		estimateFlag = estimate[0]
	}

	gasPrice := new(big.Int).Add(header.BaseFee, tx.GasTipCap())
	if gasPrice.Cmp(tx.GasFeeCap()) > 0 {
		gasPrice = tx.GasFeeCap()
	}
	gasPriceUint256, _ := uint256.FromBig(gasPrice)

	preCharge, err := BuyGasRip7560Transaction(chainConfig, gp, header, tx, statedb, gasPriceUint256)
	if err != nil {
		return nil, err
	}

	sender := tx.Rip7560TransactionData().Sender
	blockContext := NewEVMBlockContext(header, bc, author, chainConfig, statedb)
	txContext := vm.TxContext{
		Origin:   *sender,
		GasPrice: gasPrice,
	}
	evm := vm.NewEVM(blockContext, txContext, statedb, chainConfig, cfg)

	/*** Nonce Validation Frame ***/
	var nonceValidationUsedGas uint64
	nonceValidationMsg := prepareNonceValidationMessage(tx, chainConfig)
	if nonceValidationMsg != nil {
		resultNonceManager, err := ApplyMessage(evm, nonceValidationMsg, gp)
		if err != nil {
			return nil, err
		}
		if resultNonceManager.Err != nil {
			return nil, resultNonceManager.Err
		}
		nonceValidationUsedGas = resultNonceManager.UsedGas
	} else {
		err := CheckNonceRip7560(tx.Rip7560TransactionData(), statedb)
		if err != nil {
			return nil, err
		}
		// Use legacy nonce validation
		stNonce := statedb.GetNonce(*tx.Rip7560TransactionData().Sender)
		if stNonce != 0 {
			statedb.SetNonce(txContext.Origin, stNonce+1)
		}
	}

	/*** Deployer Frame ***/
	deployerMsg := prepareDeployerMessage(tx, chainConfig, nonceValidationUsedGas)
	var deploymentUsedGas uint64
	if deployerMsg != nil {
		var err error
		var resultDeployer *ExecutionResult
		if statedb.GetCodeSize(*sender) != 0 {
			err = errors.New("sender already deployed")
		} else {
			resultDeployer, err = ApplyMessage(evm, deployerMsg, gp)
		}
		if err == nil && resultDeployer != nil {
			err = resultDeployer.Err
			deploymentUsedGas = resultDeployer.UsedGas
		}
		if err == nil && statedb.GetCodeSize(*sender) == 0 {
			err = errors.New("sender not deployed")
		}
		if err != nil {
			return nil, fmt.Errorf("account deployment failed: %v", err)
		}
		// TODO : would be handled inside IntrinsicGas
		deploymentUsedGas = resultDeployer.UsedGas + params.TxGasContractCreation
	}

	/*** Account Validation Frame ***/
	signer := types.MakeSigner(chainConfig, header.Number, header.Time)
	signingHash := signer.Hash(tx)
	accountValidationMsg, err := prepareAccountValidationMessage(tx, chainConfig, signingHash, nonceValidationUsedGas, deploymentUsedGas)
	resultAccountValidation, err := ApplyMessage(evm, accountValidationMsg, gp)
	if err != nil {
		return nil, err
	}
	if resultAccountValidation.Err != nil {
		return nil, resultAccountValidation.Err
	}
	validAfter, validUntil, err := validateAccountReturnData(resultAccountValidation.ReturnData, estimateFlag)
	if err != nil {
		return nil, err
	}
	err = validateValidityTimeRange(header.Time, validAfter, validUntil)
	if err != nil {
		return nil, err
	}

	/*** Paymaster Validation Frame ***/
	paymasterContext, pmValidationUsedGas, pmValidAfter, pmValidUntil, err := applyPaymasterValidationFrame(tx, chainConfig, signingHash, evm, gp, statedb, header, estimateFlag)
	if err != nil {
		return nil, err
	}
	vpr := &ValidationPhaseResult{
		Tx:                     tx,
		TxHash:                 tx.Hash(),
		PreCharge:              preCharge,
		EffectiveGasPrice:      gasPriceUint256,
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

	return vpr, nil
}

func applyPaymasterValidationFrame(tx *types.Transaction, chainConfig *params.ChainConfig, signingHash common.Hash, evm *vm.EVM, gp *GasPool, statedb *state.StateDB, header *types.Header, estimateFlag bool) ([]byte, uint64, uint64, uint64, error) {
	var pmValidationUsedGas uint64
	var paymasterContext []byte
	var pmValidAfter uint64
	var pmValidUntil uint64
	paymasterMsg, err := preparePaymasterValidationMessage(tx, chainConfig, signingHash)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	if paymasterMsg != nil {
		resultPm, err := ApplyMessage(evm, paymasterMsg, gp)
		if err != nil {
			return nil, 0, 0, 0, err
		}
		if resultPm.Failed() {
			return nil, 0, 0, 0, resultPm.Err
		}
		pmValidationUsedGas = resultPm.UsedGas
		paymasterContext, pmValidAfter, pmValidUntil, err = validatePaymasterReturnData(resultPm.ReturnData, estimateFlag)
		if err != nil {
			return nil, 0, 0, 0, err
		}
		err = validateValidityTimeRange(header.Time, pmValidAfter, pmValidUntil)
		if err != nil {
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

func ApplyRip7560ExecutionPhase(config *params.ChainConfig, vpr *ValidationPhaseResult, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, cfg vm.Config) (*ExecutionResult, *ExecutionResult, uint64, error) {
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
		return nil, nil, 0, err
	}

	var paymasterPostOpResult *ExecutionResult
	if len(vpr.PaymasterContext) != 0 {
		paymasterPostOpResult, err = applyPaymasterPostOpFrame(vpr, executionResult, evm, gp)
		if err != nil {
			return nil, nil, 0, err
		}
		// revert the execution phase changes
		if paymasterPostOpResult.Failed() {
			statedb.RevertToSnapshot(snapshot)
		}
	}

	gasUsed :=
		vpr.NonceValidationUsedGas +
			vpr.ValidationUsedGas +
			vpr.DeploymentUsedGas +
			vpr.PmValidationUsedGas +
			executionResult.UsedGas
	if paymasterPostOpResult != nil {
		gasUsed +=
			paymasterPostOpResult.UsedGas
	}

	// calculation for intrinsicGas
	// TODO: integrated with code in state_transition
	rules := evm.ChainConfig().Rules(evm.Context.BlockNumber, evm.Context.Random != nil, evm.Context.Time)
	intrGas, err := IntrinsicGasWithOption(vpr.Tx.Data(), vpr.Tx.AccessList(), false, rules.IsHomestead, rules.IsIstanbul, rules.IsShanghai, true, false)
	if err != nil {
		return nil, nil, 0, err
	}
	gasUsed += intrGas

	// apply a penalty && refund gas
	// TODO: If this value is not persistent, it should be modified to be managed on-chain config
	const UNUSED_GAS_PENALTY_PERCENT = 10
	//gasPenalty := (prepaidGas.Uint64() - cumulativeGasUsed) * UNUSED_GAS_PENALTY_PERCENT / 100
	var gasPenalty uint64 = 0
	gasUsed += gasPenalty

	refundPayer(vpr, statedb, gasUsed, gp)

	// payments for rollup gas expenses to recipients
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), evm.Context.BaseFee)
	amtU256, overflow := uint256.FromBig(gasCost)
	if overflow {
		return nil, nil, 0, fmt.Errorf("optimism gas cost overflows U256: %d", gasCost)
	}
	statedb.AddBalance(params.OptimismBaseFeeRecipient, amtU256)
	if l1Cost := evm.Context.L1CostFunc(vpr.Tx.RollupCostData(), evm.Context.Time); l1Cost != nil {
		amtU256, overflow = uint256.FromBig(l1Cost)
		if overflow {
			return nil, nil, 0, fmt.Errorf("optimism l1 cost overflows U256: %d", l1Cost)
		}
		statedb.AddBalance(params.OptimismL1FeeRecipient, amtU256)
	}

	return executionResult, paymasterPostOpResult, gasUsed, nil
}

func prepareNonceValidationMessage(baseTx *types.Transaction, chainConfig *params.ChainConfig) *Message {
	tx := baseTx.Rip7560TransactionData()

	// TODO(sm-stack): add error handling for bigNonce value over 32 bytes
	key := make([]byte, 32)
	fromBig, _ := uint256.FromBig(tx.BigNonce)
	fromBig.WriteToSlice(key)

	nonceValidationData := make([]byte, 0)
	nonceValidationData = append(nonceValidationData[:], tx.Sender.Bytes()...)
	nonceValidationData = append(nonceValidationData[:], key...)

	// Use legacy nonce validation if the key is all zeros
	if bytes.Equal(key[:24], make([]byte, 24)) {
		return nil
	}

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
	if tx.Deployer == nil || tx.Deployer.Cmp(common.Address{}) == 0 {
		return nil
	}
	return &Message{
		From:              config.DeployerCallerAddress,
		To:                tx.Deployer,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas - nonceValidationUsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              tx.DeployerData,
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
	if tx.Paymaster == nil {
		return nil, nil
	}
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
		To:                tx.Paymaster,
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
	return &Message{
		From:              chainConfig.EntryPointAddress,
		To:                tx.Paymaster,
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

func validateAccountReturnData(data []byte, estimateFlag bool) (uint64, uint64, error) {
	if len(data) != 32 {
		return 0, 0, errors.New("invalid account return data length")
	}
	magicExpected, validUntil, validAfter := UnpackValidationData(data)
	//todo: we check first 8 bytes of the 20-byte address (the rest is expected to be zeros)
	if magicExpected != MAGIC_VALUE_SENDER {
		if magicExpected == MAGIC_VALUE_SIGFAIL {
			if !estimateFlag {
				return 0, 0, errors.New("account signature error")
			}
		}
		return 0, 0, errors.New("account did not return correct MAGIC_VALUE")
	}
	return validAfter, validUntil, nil
}

func validatePaymasterReturnData(data []byte, estimateFlag bool) ([]byte, uint64, uint64, error) {
	if len(data) < 32 {
		return nil, 0, 0, errors.New("invalid paymaster return data length")
	}
	validationData, context, err := UnpackPaymasterValidationReturn(data)
	if err != nil {
		return nil, 0, 0, err
	}
	magicExpected, validUntil, validAfter := UnpackValidationData(validationData)
	if magicExpected != MAGIC_VALUE_PAYMASTER {
		return nil, 0, 0, errors.New("paymaster did not return correct MAGIC_VALUE")
	}
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
