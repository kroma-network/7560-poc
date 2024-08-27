package rip7560

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"math/big"
	"testing"
)

var DEFAULT_PAYMASTER = common.HexToAddress("0xaaaaaaaaaabbbbbbbbbbccccccccccdddddddddd")

func TestPaymasterValidationFailure_nobalance(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(push(0), vm.DUP1, vm.REVERT), 1), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit: 1000000,
		GasFeeCap:          big.NewInt(1),
		Paymaster:          &DEFAULT_PAYMASTER,
	}, "insufficient funds for gas * price + value: address 0xaaAaaAAAAAbBbbbbBbBBCCCCcCCCcCdddDDDdddd have 1 want 1015000")
}

func TestPaymasterValidationFailure_oog(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(push(0), vm.DUP1, vm.REVERT), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit: 1000000,
		GasFeeCap:          big.NewInt(1),
		Paymaster:          &DEFAULT_PAYMASTER,
	}, "out of gas")
}
func TestPaymasterValidationFailure_revert(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(push(0), vm.DUP1, vm.REVERT), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          uint64(1000000),
		GasFeeCap:                   big.NewInt(1),
		Paymaster:                   &DEFAULT_PAYMASTER,
		PaymasterValidationGasLimit: 1000000,
	}, "execution reverted")
}

func TestPaymasterValidationFailure_unparseable_return_value(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createAccountCode(), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1000000,
		PaymasterValidationGasLimit: 1000000,
		GasFeeCap:                   big.NewInt(1),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "paymaster return data: too short")
}

func TestPaymasterValidationFailure_wrong_magic(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), returnWithData(paymasterReturnValue(1, 2, 3, []byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1000000,
		PaymasterValidationGasLimit: 1000000,
		GasFeeCap:                   big.NewInt(1),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "paymaster did not return correct MAGIC_VALUE")
}

func TestPaymasterValidationFailure_contextTooLarge(t *testing.T) {
	//paymaster returning huge context.
	// first word is magic return value
	// 2nd word is offset (fixed 64)
	// 3rd word is length of context (max+1)
	// then we return the total length of above (context itself is uninitialized string of max+1 zeroes)
	pmCode := createCode(
		//vm.PUSH1, 1, vm.PUSH1, 0, vm.RETURN,
		copyToMemory(core.PackValidationData(core.MAGIC_VALUE_PAYMASTER, 0, 0), 0),
		copyToMemory(asBytes32(64), 32),
		copyToMemory(asBytes32(core.PAYMASTER_MAX_CONTEXT_SIZE+1), 64),
		push(core.PAYMASTER_MAX_CONTEXT_SIZE+96+1), push(0), vm.RETURN)

	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), pmCode, DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1000000,
		PaymasterValidationGasLimit: 1000000,
		GasFeeCap:                   big.NewInt(1),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "paymaster return data: context too large")
}

func TestPaymasterValidationFailure_validAfter(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), returnWithData(paymasterReturnValue(core.MAGIC_VALUE_PAYMASTER, 300, 200, []byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1000000,
		PaymasterValidationGasLimit: 1000000,
		GasFeeCap:                   big.NewInt(1),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "RIP-7560 transaction validity not reached yet")
}

func TestPaymasterValidationFailure_validUntil(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), returnWithData(paymasterReturnValue(core.MAGIC_VALUE_PAYMASTER, 1, 0, []byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1000000,
		PaymasterValidationGasLimit: 1000000,
		GasFeeCap:                   big.NewInt(1),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "RIP-7560 transaction validity expired")
}

func TestPaymasterValidation_ok(t *testing.T) {
	handleValidation(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), returnWithData(paymasterReturnValue(core.MAGIC_VALUE_PAYMASTER, 0, 0, []byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1000000,
		PaymasterValidationGasLimit: 1000000,
		GasFeeCap:                   big.NewInt(1),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "ok")
}
