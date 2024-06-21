package native

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/holiman/uint256"
	"math/big"
	"regexp"
	"strconv"
	"sync/atomic"
)

func init() {
	tracers.DefaultDirectory.Register("rip7560Validation", newRip7560Tracer, false)
}

func newRip7560Tracer(ctx *tracers.Context, cfg json.RawMessage) (tracers.Tracer, error) {
	var config callTracerConfig
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}
	}
	return &rip7560ValidationTracer{
		calls:  make([]callFrame, 0),
		config: config,
	}, nil
}

type Level struct {
	TopLevelMethodSig     hexutil.Bytes        `json:"topLevelMethodSig,omitempty"`
	TopLevelTargetAddress common.Address       `json:"topLevelTargetAddress,omitempty"`
	Opcodes               Counts               `json:"opcodes,omitempty"`
	Access                AccessMap            `json:"access,omitempty"`
	ContractSize          ContractSizeMap      `json:"contractSize,omitempty"`
	ExtCodeAccessInfo     ExtCodeAccessInfoMap `json:"extCodeAccessInfo,omitempty"`
	Oog                   bool                 `json:"oog,omitempty"`
}

type Counts = map[string]int
type HexMap = map[string]string

// AccessInfo provides context on read and write counts by storage slots.
type AccessInfo struct {
	Reads  HexMap `json:"reads"`
	Writes Counts `json:"writes"`
}

type AccessMap = map[common.Address]AccessInfo

// ContractSizeInfo provides context on the code size and call type used to access upstream contracts.
type ContractSizeInfo struct {
	ContractSize int    `json:"contractSize"`
	Opcode       string `json:"opcode"`
}

type ContractSizeMap map[common.Address]ContractSizeInfo

// ExtCodeAccessInfoMap provides context on potentially illegal use of EXTCODESIZE.
type ExtCodeAccessInfoMap map[common.Address]string

type OpInfo struct {
	Opcode    string     `json:"opcode"`
	StackTop3 []*big.Int `json:"stackTop3"`
}

// Array fields contain of all access details of all validation frames
type rip7560ValidationTracer struct {
	noopTracer
	env *vm.EVM

	callsFromEntryPoint []*Level
	currentLevel        *Level
	topLevelCallCounter int
	keccak              []string
	calls               []callFrame
	logs                []callLog
	// debug?
	lastOp           vm.OpCode
	lastThreeOpcodes []OpInfo

	gasLimit  uint64
	config    callTracerConfig
	interrupt atomic.Bool // Atomic flag to signal execution interruption
	reason    error       // Textual reason for the interruption
}

type Rip7560ValidationResult struct {
	CallsFromEntryPoint []*Level    `json:"callsFromEntryPoint"`
	Keccak              []string    `json:"keccak"`
	Logs                []callLog   `json:"logs"`
	Calls               []callFrame `json:"calls"`
	Debug               []string    `json:"debug"`
}

func (t *rip7560ValidationTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env
	toCopy := to
	t.calls = append(t.calls, callFrame{
		Type:  vm.CALL,
		From:  from,
		To:    &toCopy,
		Input: common.CopyBytes(input),
		Gas:   t.gasLimit,
		Value: value,
	})
	if create {
		t.calls[len(t.calls)-1].Type = vm.CREATE
	}

	topLevelTargetAddress := toCopy
	topLevelMethodSig := input[0:4]

	t.currentLevel = &Level{
		TopLevelMethodSig:     topLevelMethodSig,
		TopLevelTargetAddress: topLevelTargetAddress,
		Access:                AccessMap{},
		Opcodes:               Counts{},
		ExtCodeAccessInfo:     ExtCodeAccessInfoMap{},
		ContractSize:          ContractSizeMap{},
	}
	t.callsFromEntryPoint = append(t.callsFromEntryPoint, t.currentLevel)
	t.topLevelCallCounter++
}

func (t *rip7560ValidationTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	t.calls[len(t.calls)-1].processOutput(output, err)

	t.callsFromEntryPoint[len(t.callsFromEntryPoint)-1] = &Level{
		Oog:                   t.currentLevel.Oog,
		Access:                t.currentLevel.Access,
		Opcodes:               t.currentLevel.Opcodes,
		ExtCodeAccessInfo:     t.currentLevel.ExtCodeAccessInfo,
		ContractSize:          t.currentLevel.ContractSize,
		TopLevelMethodSig:     t.currentLevel.TopLevelMethodSig,
		TopLevelTargetAddress: t.currentLevel.TopLevelTargetAddress,
	}
}

func (t *rip7560ValidationTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// skip if the previous op caused an error
	if err != nil {
		return
	}

	stack := scope.Stack
	stackData := stack.Data()
	stackSize := len(stackData)
	stackTop3 := make([]uint256.Int, 3)
	for i := 0; i < 3 && i < stackSize; i++ {
		stackTop3 = append(stackTop3, stackData[stackSize-i-1])
	}
	if len(t.lastThreeOpcodes) > 3 {
		t.lastThreeOpcodes = t.lastThreeOpcodes[1:]
	}

	if gas < cost || (op == vm.SSTORE && gas < 2300) {
		t.currentLevel.Oog = true
	}

	var lastOpInfo OpInfo
	if t.lastThreeOpcodes != nil && len(t.lastThreeOpcodes) > 1 {
		lastOpInfo = t.lastThreeOpcodes[len(t.lastThreeOpcodes)-2]
	}
	matched, _ := regexp.MatchString("^(EXT.*)$", lastOpInfo.Opcode)
	if matched {
		addr := lastOpInfo.StackTop3[0].Text(16)
		addrHex := common.HexToAddress(addr[2:])
		last3opcodesString := ""
		for _, x := range t.lastThreeOpcodes {
			last3opcodesString += x.Opcode + ","
		}
		last3opcodesString = last3opcodesString[:len(last3opcodesString)-1]
		matched, _ = regexp.MatchString("^(\\w+),EXTCODESIZE,ISZERO$", last3opcodesString)
		if !matched {
			t.currentLevel.ExtCodeAccessInfo[addrHex] = op.String()
		}
	}

	isAllowedPrecompiled := func(address string) bool {
		addrHex := address[2:]
		addressInt, _ := new(big.Int).SetString(addrHex, 16)
		return addressInt.Cmp(big.NewInt(0)) > 0 && addressInt.Cmp(big.NewInt(10)) < 0
	}

	matched, _ = regexp.MatchString("^(EXT.*|CALL|CALLCODE|DELEGATECALL|STATICCALL)$", op.String())
	if matched {
		idx := 1
		if op.String()[:3] == "EXT" {
			idx = 0
		} else {
			if t.lastOp == vm.GAS {
				t.countSlot(t.currentLevel.Opcodes, "GAS")
			}
		}
		addr := stackData[stackSize-idx-1].Hex()
		addrHex := common.HexToAddress(addr)
		if _, exists := t.currentLevel.ContractSize[addrHex]; !exists && !isAllowedPrecompiled(addr) {
			t.currentLevel.ContractSize[addrHex] = ContractSizeInfo{
				ContractSize: len(t.env.StateDB.GetCode(common.HexToAddress(addr))),
				Opcode:       op.String(),
			}
		}
	}

	switch op {
	case vm.REVERT, vm.RETURN:
		if depth == 0 {
			offset := int(stackData[stackSize-1].Uint64())
			length := int(stackData[stackSize-2].Uint64())
			data := scope.Memory.Data()[offset : offset+length][:4000]
			t.calls = append(t.calls, callFrame{
				Type:    op,
				GasUsed: 0,
				Input:   data,
			})
		}
		t.lastThreeOpcodes = []OpInfo{}
	case vm.SLOAD, vm.SSTORE:
		slot := stackData[stackSize-1].Hex()
		addr := scope.Contract.Address().Hex()
		addrHex := common.HexToAddress(addr)
		if t.currentLevel.Access == nil {
			t.currentLevel.Access = AccessMap{}
		}
		access, exists := t.currentLevel.Access[addrHex]
		if !exists {
			access = AccessInfo{
				Reads:  make(HexMap),
				Writes: make(Counts),
			}
			t.currentLevel.Access[addrHex] = access
		}

		if op == vm.SLOAD {
			if _, readExists := access.Reads[slot]; !readExists {
				if _, writeExists := access.Writes[slot]; !writeExists {
					access.Reads[slot] = t.env.StateDB.GetState(common.HexToAddress(addr), common.HexToHash(slot)).Hex()
				}
			}
		} else {
			t.countSlot(access.Writes, slot)
		}
	case vm.KECCAK256:
		offset := int(stackData[stackSize-1].Uint64())
		length := int(stackData[stackSize-2].Uint64())
		if length > 20 && length < 512 {
			t.keccak = append(t.keccak, hexutil.Encode(scope.Memory.Data()[offset:offset+length]))
		}
	case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
		count, _ := strconv.Atoi(op.String()[3:])
		offset := int(stackData[stackSize-count-1].Uint64())
		length := int(stackData[stackSize-count-2].Uint64())
		tpcs := []common.Hash{}
		for i := 0; i < count; i++ {
			tpcs = append(tpcs, common.BytesToHash(stackData[stackSize-i-1].Bytes()))
		}
		data := scope.Memory.Data()[offset : offset+length]
		t.logs = append(t.logs, callLog{
			Topics: tpcs,
			Data:   hexutil.Bytes(data),
		})
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *rip7560ValidationTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if t.config.OnlyTopCall {
		return
	}
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}

	toCopy := to
	call := callFrame{
		Type:  typ,
		From:  from,
		To:    &toCopy,
		Input: common.CopyBytes(input),
		Gas:   gas,
		Value: value,
	}
	t.calls = append(t.calls, call)
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *rip7560ValidationTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if t.config.OnlyTopCall {
		return
	}
	size := len(t.calls)
	if size <= 1 {
		return
	}
	// pop call
	call := t.calls[size-1]
	t.calls = t.calls[:size-1]
	size -= 1

	call.GasUsed = gasUsed
	call.processOutput(output, err)
	t.calls[size-1].Calls = append(t.calls[size-1].Calls, call)
}

func (t *rip7560ValidationTracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
}

func (t *rip7560ValidationTracer) CaptureTxEnd(restGas uint64) {
	t.calls[len(t.calls)-1].GasUsed = t.gasLimit - restGas
	if t.config.WithLog {
		// Logs are not emitted when the call fails
		clearFailedLogs(&t.calls[len(t.calls)-1], false)
	}
}

func (t *rip7560ValidationTracer) GetResult() (json.RawMessage, error) {
	if len(t.calls) > 4 {
		return nil, errors.New("incorrect number of top-level calls")
	}

	if t.calls[len(t.calls)-1].Type == vm.STOP {
		t.calls[len(t.calls)-1].Error = "failed deposit transaction"
	}

	resultJson, err := json.Marshal(&Rip7560ValidationResult{
		CallsFromEntryPoint: t.callsFromEntryPoint,
		Keccak:              t.keccak,
		Calls:               t.calls,
		Logs:                t.logs,
		Debug:               []string{},
	})
	if err != nil {
		return nil, err
	}

	return json.RawMessage(resultJson), t.reason
}

func (t *rip7560ValidationTracer) Stop(err error) {
	t.reason = err
	t.interrupt.Store(true)
}

func (t *rip7560ValidationTracer) countSlot(m Counts, key string) {
	if _, exists := m[key]; exists {
		m[key]++
	} else {
		m[key] = 1
	}
}
