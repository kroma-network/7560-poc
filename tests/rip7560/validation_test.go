package rip7560

import (
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/tests"
	"github.com/status-im/keycard-go/hexutils"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestPackValidationData(t *testing.T) {
	// --------------- after 6bytes     before 6 bytes   magic 20 bytes
	validationData := "000000000002" + "000000000001" + "0000000000000000000000000000000000001234"
	packed, _ := new(big.Int).SetString(validationData, 16)
	assert.Equal(t, packed.Text(16), new(big.Int).SetBytes(core.PackValidationData(0x1234, 1, 2)).Text(16))
}

func TestUnpackValidationData(t *testing.T) {
	packed := core.PackValidationData(0xdead, 0xcafe, 0xface)
	magic, until, after := core.UnpackValidationData(packed)
	assert.Equal(t, []uint64{0xdead, 0xcafe, 0xface}, []uint64{magic, until, after})
}

func TestValidationFailure_OOG(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1),
		GasFeeCap:     big.NewInt(1),
	}, "out of gas")
}

func TestValidationFailure_no_balance(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 1), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1),
		GasFeeCap:     big.NewInt(1),
	}, "insufficient funds for gas * price + value: address 0x1111111111222222222233333333334444444444 have 1 want 15001")
}

func TestValidationFailure_sigerror(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, returnWithData(core.PackValidationData(core.MAGIC_VALUE_SIGFAIL, 0, 0)), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "account signature error")
}

func TestValidationFailure_validAfter(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER,
		returnWithData(core.PackValidationData(core.MAGIC_VALUE_SENDER, 300, 200)), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "RIP-7560 transaction validity not reached yet")
}

func TestValidationFailure_validUntil(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER,
		returnWithData(core.PackValidationData(core.MAGIC_VALUE_SENDER, 1, 0)), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "RIP-7560 transaction validity expired")
}

func TestValidation_ok(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "ok")
}

func TestValidation_ok_paid(t *testing.T) {
	aatx := types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}
	tb := newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), DEFAULT_BALANCE)
	handleTransaction(tb, aatx, "ok")

	maxCost := new(big.Int).SetUint64(aatx.ValidationGas + aatx.PaymasterGas + aatx.Gas)
	maxCost.Mul(maxCost, aatx.GasFeeCap)
}

func TestValidationFailure_account_revert(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER,
		createCode(push(0), vm.DUP1, vm.REVERT), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "execution reverted")
}

func TestValidationFailure_account_revert_with_reason(t *testing.T) {
	// cast abi-encode 'Error(string)' hello
	reason := hexutils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000568656c6c6f000000000000000000000000000000000000000000000000000000")
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER,
		revertWithData(reason), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "execution reverted")
}

func TestValidationFailure_account_wrong_return_length(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER,
		returnWithData([]byte{1, 2, 3}), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "invalid account return data length")
}

func TestValidationFailure_account_no_return_value(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER,
		returnWithData([]byte{}), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "invalid account return data length")
}

func TestValidationFailure_account_wrong_return_value(t *testing.T) {
	// create buffer of 32 byte array
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER,
		returnWithData(make([]byte, 32)),
		DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000),
		GasFeeCap:     big.NewInt(1),
	}, "account did not return correct MAGIC_VALUE")
}

func handleTransaction(tb *testContextBuilder, aatx types.Rip7560AccountAbstractionTx, expectedErr string) {
	t := tb.build()
	if aatx.Sender == nil {
		//pre-deployed sender account
		Sender := common.HexToAddress(DEFAULT_SENDER)
		aatx.Sender = &Sender
	}
	tx := types.NewTx(&aatx)

	var state = tests.MakePreState(rawdb.NewMemoryDatabase(), t.genesisAlloc, false, rawdb.HashScheme)
	defer state.Close()

	state.StateDB.SetTxContext(tx.Hash(), 0)
	_, _, _, err := core.HandleRip7560Transactions([]*types.Transaction{tx}, 0, state.StateDB, &common.Address{}, t.genesisBlock.Header(), t.gaspool, t.genesis.Config, t.chainContext, vm.Config{})

	errStr := "ok"
	if err != nil {
		errStr = err.Error()
	}
	assert.Equal(t.t, expectedErr, errStr)
}

func handleValidation(tb *testContextBuilder, aatx types.Rip7560AccountAbstractionTx, expectedErr string) {
	t := tb.build()
	if aatx.Sender == nil {
		//pre-deployed sender account
		Sender := common.HexToAddress(DEFAULT_SENDER)
		aatx.Sender = &Sender
	}
	tx := types.NewTx(&aatx)

	var state = tests.MakePreState(rawdb.NewMemoryDatabase(), t.genesisAlloc, false, rawdb.HashScheme)
	defer state.Close()

	state.StateDB.SetTxContext(tx.Hash(), 0)
	_, err := core.ApplyRip7560ValidationPhases(t.genesis.Config, t.chainContext, &common.Address{}, t.gaspool, state.StateDB, t.genesisBlock.Header(), tx, vm.Config{})

	errStr := "ok"
	if err != nil {
		errStr = err.Error()
	}
	assert.Equal(t.t, expectedErr, errStr)
}

//test failure on non-rip7560

//IntrinsicGas: for validation frame, should return the max possible gas.
// - execution should be "free" (and refund the excess)
// geth increment nonce before "call" our validation frame. (in ApplyMessage)
