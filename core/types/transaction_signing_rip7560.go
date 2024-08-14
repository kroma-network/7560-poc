package types

import (
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

type rip7560Signer struct{ londonSigner }

func NewRIP7560Signer(chainId *big.Int) Signer {
	return rip7560Signer{londonSigner{eip2930Signer{NewEIP155Signer(chainId)}}}
}

func (s rip7560Signer) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() == Rip7560Type {
		return *tx.Rip7560TransactionData().Sender, nil
	} else if tx.Type() != Rip7560BundleHeaderType {
		return [20]byte{}, nil
	} else {
		return s.londonSigner.Sender(tx)
	}
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s rip7560Signer) Hash(tx *Transaction) common.Hash {
	if tx.Type() != Rip7560Type && tx.Type() != Rip7560BundleHeaderType {
		return s.londonSigner.Hash(tx)
	}
	aatx := tx.Rip7560TransactionData()
	return prefixedRlpHash(
		tx.Type(),
		[]interface{}{
			s.chainId,
			aatx.BigNonce,
			aatx.Sender,
			aatx.Deployer,
			aatx.DeployerData,
			aatx.Paymaster,
			aatx.PaymasterData,
			tx.Data(),
			aatx.BuilderFee,
			tx.GasTipCap(),
			tx.GasFeeCap(),
			aatx.ValidationGas,
			aatx.PaymasterGas,
			aatx.PostOpGas,
			tx.Gas(),
			tx.AccessList(),
		})
}
