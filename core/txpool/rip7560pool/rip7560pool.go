package rip7560pool

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"math/big"
	"sync"
	"sync/atomic"
)

type Config struct {
	MaxBundleSize uint
	MaxBundleGas  uint
}

// Rip7560BundlerPool is the transaction pool dedicated to RIP-7560 AA transactions.
// This implementation relies on an external bundler process to perform most of the hard work.
type Rip7560BundlerPool struct {
	config      Config
	chain       legacypool.BlockChain
	txFeed      event.Feed
	currentHead atomic.Pointer[types.Header] // Current head of the blockchain

	pendingBundles  []*types.ExternallyReceivedBundle
	includedBundles map[common.Hash]*types.BundleReceipt

	mu sync.Mutex

	coinbase common.Address
}

func (pool *Rip7560BundlerPool) Init(_ uint64, head *types.Header, _ txpool.AddressReserver) error {
	pool.pendingBundles = make([]*types.ExternallyReceivedBundle, 0)
	pool.includedBundles = make(map[common.Hash]*types.BundleReceipt)
	pool.currentHead.Store(head)
	return nil
}

func (pool *Rip7560BundlerPool) Close() error {
	return nil
}

func (pool *Rip7560BundlerPool) Reset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	newIncludedBundles := pool.gatherIncludedBundlesStats(newHead)
	for _, included := range newIncludedBundles {
		pool.includedBundles[included.BundleHash] = included
	}

	pendingBundles := make([]*types.ExternallyReceivedBundle, 0, len(pool.pendingBundles))
	for _, bundle := range pool.pendingBundles {
		nextBlock := big.NewInt(0).Add(newHead.Number, big.NewInt(1))
		if bundle.ValidForBlock.Cmp(nextBlock) == 0 {
			pendingBundles = append(pendingBundles, bundle)
		}
	}
	pool.pendingBundles = pendingBundles
	pool.currentHead.Store(newHead)
}

// For simplicity, this function assumes 'Reset' called for each new block sequentially.
func (pool *Rip7560BundlerPool) gatherIncludedBundlesStats(newHead *types.Header) map[common.Hash]*types.BundleReceipt {
	// 1. Is there a bundle included in the block?

	// note that in 'clique' mode Coinbase is always set to 0x000...000
	if newHead.Coinbase.Cmp(pool.coinbase) != 0 && newHead.Coinbase.Cmp(common.Address{}) != 0 {
		// not our block
		return nil
	}

	// get all transaction hashes in block
	add := pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
	block := add.Transactions()

	receipts := pool.chain.GetReceiptsByHash(add.Hash())
	// match transactions in block to bundle ?

	includedBundles := make(map[common.Hash]*types.BundleReceipt)

	// 'pendingBundles' length is expected to be single digits, probably a single bundle in most cases
	for _, bundle := range pool.pendingBundles {
		if len(block) < len(bundle.Transactions) {
			// this bundle does not even fit this block
			continue
		}
		for i := 0; i < len(block); i++ {
			transactions := make(types.Transactions, 0)
			for j := 0; j < len(bundle.Transactions); j++ {
				blockTx := block[i]
				bundleTx := bundle.Transactions[j]
				if bundleTx.Hash().Cmp(blockTx.Hash()) == 0 {
					// tx hash has matched
					transactions = append(transactions, blockTx)
					if j == len(bundle.Transactions)-1 {
						// FOUND BUNDLE IN BLOCK
						receipt := createBundleReceipt(add, bundle.BundleHash, transactions, receipts)
						includedBundles[bundle.BundleHash] = receipt
					} else {
						// let's see if next tx in bundle matches
						i++
					}
				}
			}
		}

	}
	return includedBundles
}

func createBundleReceipt(block *types.Block, BundleHash common.Hash, transactions types.Transactions, blockReceipts types.Receipts) *types.BundleReceipt {
	receipts := make(types.Receipts, 0)

OuterLoop:
	for _, transaction := range transactions {
		for _, receipt := range blockReceipts {
			if receipt.TxHash == transaction.Hash() {
				receipts = append(receipts, receipt)
				continue OuterLoop
			}
		}
		panic("receipt not found for transaction")
	}

	var gasUsed uint64 = 0
	var gasPaidPriority = big.NewInt(0)

	for _, receipt := range receipts {
		gasUsed += receipt.GasUsed
		priorityFeePerGas := big.NewInt(0).Sub(receipt.EffectiveGasPrice, block.BaseFee())
		priorityFeePaid := big.NewInt(0).Mul(big.NewInt(int64(gasUsed)), priorityFeePerGas)
		gasPaidPriority = big.NewInt(0).Add(gasPaidPriority, priorityFeePaid)
	}

	return &types.BundleReceipt{
		BundleHash:          BundleHash,
		Count:               uint64(len(transactions)),
		Status:              0,
		BlockNumber:         block.NumberU64(),
		BlockHash:           block.Hash(),
		TransactionReceipts: receipts,
		GasUsed:             gasUsed,
		GasPaidPriority:     gasPaidPriority,
		BlockTimestamp:      block.Time(),
	}
}

// SetGasTip is ignored by the External Bundler AA sub pool.
func (pool *Rip7560BundlerPool) SetGasTip(_ *big.Int) {}

func (pool *Rip7560BundlerPool) Has(hash common.Hash) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	tx := pool.Get(hash)
	return tx != nil
}

func (pool *Rip7560BundlerPool) Get(hash common.Hash) *types.Transaction {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, bundle := range pool.pendingBundles {
		for _, tx := range bundle.Transactions {
			if tx.Hash().Cmp(hash) == 0 {
				return tx
			}
		}
	}
	return nil
}

func (pool *Rip7560BundlerPool) Add(_ []*types.Transaction, _ bool, _ bool) []error {
	return nil
}

func (pool *Rip7560BundlerPool) Pending(_ txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	return nil
}

func (pool *Rip7560BundlerPool) PendingRip7560Bundle() (*types.ExternallyReceivedBundle, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	bundle := pool.selectExternalBundle()
	return bundle, nil
}

// SubscribeTransactions is not needed for the External Bundler AA sub pool and 'ch' will never be sent anything.
func (pool *Rip7560BundlerPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, _ bool) event.Subscription {
	return pool.txFeed.Subscribe(ch)
}

// Nonce is only used from 'GetPoolNonce' which is not relevant for AA transactions.
func (pool *Rip7560BundlerPool) Nonce(_ common.Address) uint64 {
	return 0
}

// Stats function not implemented for the External Bundler AA sub pool.
func (pool *Rip7560BundlerPool) Stats() (int, int) {
	return 0, 0
}

// Content function not implemented for the External Bundler AA sub pool.
func (pool *Rip7560BundlerPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return nil, nil
}

// ContentFrom function not implemented for the External Bundler AA sub pool.
func (pool *Rip7560BundlerPool) ContentFrom(_ common.Address) ([]*types.Transaction, []*types.Transaction) {
	return nil, nil
}

// Locals are not necessary for AA Pool
func (pool *Rip7560BundlerPool) Locals() []common.Address {
	return []common.Address{}
}

func (pool *Rip7560BundlerPool) Status(_ common.Hash) txpool.TxStatus {
	panic("implement me")
}

// New creates a new RIP-7560 Account Abstraction Bundler transaction pool.
func New(config Config, chain legacypool.BlockChain, coinbase common.Address) *Rip7560BundlerPool {
	return &Rip7560BundlerPool{
		config:   config,
		chain:    chain,
		coinbase: coinbase,
	}
}

// Filter rejects all individual transactions for External Bundler AA sub pool.
func (pool *Rip7560BundlerPool) Filter(_ *types.Transaction) bool {
	return false
}

func (pool *Rip7560BundlerPool) SubmitRip7560Bundle(bundle *types.ExternallyReceivedBundle) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	currentBlock := pool.currentHead.Load().Number
	nextBlock := big.NewInt(0).Add(currentBlock, big.NewInt(1))
	log.Error("RIP-7560 bundle submitted", "validForBlock", bundle.ValidForBlock.String(), "nextBlock", nextBlock.String())
	pool.pendingBundles = append(pool.pendingBundles, bundle)
	if nextBlock.Cmp(bundle.ValidForBlock) == 0 {
		pool.txFeed.Send(core.NewTxsEvent{Txs: bundle.Transactions})
	}
	return nil
}

func (pool *Rip7560BundlerPool) GetRip7560BundleStatus(hash common.Hash) (*types.BundleReceipt, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.includedBundles[hash], nil
}

// Simply returns the bundle with the highest promised revenue by fully trusting the bundler-provided value.
func (pool *Rip7560BundlerPool) selectExternalBundle() *types.ExternallyReceivedBundle {
	var selectedBundle *types.ExternallyReceivedBundle
	for _, bundle := range pool.pendingBundles {
		if selectedBundle == nil || selectedBundle.ExpectedRevenue.Cmp(bundle.ExpectedRevenue) == -1 {
			selectedBundle = bundle
		}
	}
	return selectedBundle
}
