package hdwallet

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum"
	eth "github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	tron "github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/tyler-smith/go-bip39"
	"google.golang.org/protobuf/proto"
)

// DefaultRootDerivationPath is the root path to which custom derivation endpoints
// are appended. As such, the first account will be at m/44'/60'/0'/0, the second
// at m/44'/60'/0'/1, etc.
var DefaultRootDerivationPath = eth.DefaultRootDerivationPath

// DefaultBaseDerivationPath is the base path from which custom derivation endpoints
// are incremented. As such, the first account will be at m/44'/60'/0'/0, the second
// at m/44'/60'/0'/1, etc
var DefaultBaseDerivationPath = eth.DefaultBaseDerivationPath

const (
	issue179FixEnvar = "GO_ETHEREUM_HDWALLET_FIX_ISSUE_179"
	EthereumCoin     = "eth"
	TronCoin         = "tron"
)

type tronAccount struct {
	Address tron.Address
	URL     eth.URL
}

// Wallet is the underlying wallet struct.
type Wallet struct {
	mnemonic     string
	masterKey    *hdkeychain.ExtendedKey
	seed         []byte
	url          eth.URL
	paths        map[string]eth.DerivationPath
	ethAccounts  []eth.Account
	tronAccounts []tronAccount
	stateLock    sync.RWMutex
	fixIssue172  bool
}

func newWallet(seed []byte) (*Wallet, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		masterKey:    masterKey,
		seed:         seed,
		tronAccounts: []tronAccount{},
		ethAccounts:  []eth.Account{},
		paths:        map[string]eth.DerivationPath{},
		fixIssue172:  false || len(os.Getenv(issue179FixEnvar)) > 0,
	}, nil
}

// NewFromMnemonic returns a new wallet from a BIP-39 mnemonic.
func NewFromMnemonic(mnemonic string) (*Wallet, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invalid")
	}

	seed, err := NewSeedFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	wallet, err := newWallet(seed)
	if err != nil {
		return nil, err
	}
	wallet.mnemonic = mnemonic

	return wallet, nil
}

// NewFromSeed returns a new wallet from a BIP-39 seed.
func NewFromSeed(seed []byte) (*Wallet, error) {
	if len(seed) == 0 {
		return nil, errors.New("seed is required")
	}

	return newWallet(seed)
}

// URL implements accounts.Wallet, returning the URL of the device that
// the wallet is on, however this does nothing since this is not a hardware device.
func (w *Wallet) URL() eth.URL {
	return w.url
}

// Status implements accounts.Wallet, returning a custom status message
// from the underlying vendor-specific hardware wallet implementation,
// however this does nothing since this is not a hardware device.
func (w *Wallet) Status() (string, error) {
	return "ok", nil
}

// Open implements accounts.Wallet, however this does nothing since this
// is not a hardware device.
func (w *Wallet) Open(passphrase string) error {
	return nil
}

// Close implements accounts.Wallet, however this does nothing since this
// is not a hardware device.
func (w *Wallet) Close() error {
	return nil
}

// Accounts implements accounts.Wallet, returning the list of accounts pinned to
// the wallet. If self-derivation was enabled, the account list is
// periodically expanded based on current chain state.
func (w *Wallet) Accounts() []eth.Account {
	// Attempt self-derivation if it's running
	// Return whatever account list we ended up with
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	cpy := make([]eth.Account, len(w.ethAccounts))
	copy(cpy, w.ethAccounts)
	return cpy
}

// Contains implements accounts.Wallet and tronWallet, returning whether a particular account is
// or is not pinned into this wallet instance.
func (w *Wallet) Contains(account interface{}) bool {
	switch a := account.(type) {
	case tronAccount:
		return w.ContainsTron(a)
	case eth.Account:
		return w.ContainsEth(a)
	default:
		return false
	}
}

func (w *Wallet) ContainsEth(account eth.Account) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	_, exists := w.paths[account.Address.Hex()]
	return exists
}

func (w *Wallet) ContainsTron(account tronAccount) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	_, exists := w.paths[account.Address.String()]
	return exists
}

// Unpin unpins account from list of pinned accounts.
func (w *Wallet) Unpin(account interface{}) error {
	switch a := account.(type) {
	case tronAccount:
		return w.UnpinTron(a)
	case eth.Account:
		return w.UnpinEth(a)
	default:
		return errors.New("invalid account type")
	}
}

func (w *Wallet) UnpinEth(account eth.Account) error {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	for i, acct := range w.ethAccounts {
		if acct.Address.Hex() == account.Address.Hex() {
			w.ethAccounts = removeEthAccountAtIndex(w.ethAccounts, i)
			delete(w.paths, account.Address.Hex())
			return nil
		}
	}

	return errors.New("account not found")
}

func (w *Wallet) UnpinTron(account tronAccount) error {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	for i, acct := range w.tronAccounts {
		if acct.Address.String() == account.Address.String() {
			w.tronAccounts = removeTronAccountAtIndex(w.tronAccounts, i)
			delete(w.paths, account.Address.String())
			return nil
		}
	}

	return errors.New("account not found")
}

// SetFixIssue172 determines whether the standard (correct) bip39
// derivation path was used, or if derivation should be affected by
// Issue172 [0] which was how this library was originally implemented.
// [0] https://github.com/btcsuite/btcutil/pull/182/files
func (w *Wallet) SetFixIssue172(fixIssue172 bool) {
	w.fixIssue172 = fixIssue172
}

// Derive implements accounts.Wallet and tronWallet, deriving a new account at the specific
// derivation path. If pin is set to true, the account will be added to the list
// of tracked accounts.
func (w *Wallet) Derive(path eth.DerivationPath, pin bool) (interface{}, error) {
	// Try to derive the actual account and update its URL if successful
	w.stateLock.RLock() // Avoid device disappearing during derivation

	address, coin, err := w.deriveAddress(path)

	w.stateLock.RUnlock()

	// If an error occurred or no pinning was requested, return
	if err != nil {
		return struct{}{}, err
	}

	if coin == EthereumCoin {
		ethAddress := address.(common.Address)

		account := eth.Account{
			Address: ethAddress,
			URL: eth.URL{
				Scheme: "",
				Path:   path.String(),
			},
		}

		if !pin {
			return account, nil
		}

		// Pinning needs to modify the state
		w.stateLock.Lock()
		defer w.stateLock.Unlock()

		if _, ok := w.paths[ethAddress.Hex()]; !ok {
			w.ethAccounts = append(w.ethAccounts, account)
			w.paths[ethAddress.Hex()] = path
		}

		return account, nil
	} else {
		tronAddress := address.(tron.Address)

		account := tronAccount{
			Address: tronAddress,
			URL: eth.URL{
				Scheme: "",
				Path:   path.String(),
			},
		}

		if !pin {
			return account, nil
		}

		// Pinning needs to modify the state
		w.stateLock.Lock()
		defer w.stateLock.Unlock()

		if _, ok := w.paths[tronAddress.String()]; !ok {
			w.tronAccounts = append(w.tronAccounts, account)
			w.paths[tronAddress.String()] = path
		}

		return account, nil
	}
}

// SelfDerive implements accounts.Wallet, trying to discover accounts that the
// user used previously (based on the chain state), but ones that he/she did not
// explicitly pin to the wallet manually. To avoid chain head monitoring, self
// derivation only runs during account listing (and even then throttled).
func (w *Wallet) SelfDerive(base []eth.DerivationPath, chain ethereum.ChainStateReader) {
	// TODO: self derivation
}

// SignHash implements accounts.Wallet, which allows signing arbitrary data.
func (w *Wallet) SignHash(account interface{}, hash []byte) ([]byte, error) {
	var path eth.DerivationPath
	var ok bool

	switch a := account.(type) {
	case eth.Account:
		// Make sure the requested account is contained within
		path, ok = w.paths[a.Address.Hex()]
		if !ok {
			return nil, eth.ErrUnknownAccount
		}
	case tronAccount:
		// Make sure the requested account is contained within
		path, ok = w.paths[a.Address.String()]
		if !ok {
			return nil, eth.ErrUnknownAccount
		}
	default:
		return nil, eth.ErrUnknownAccount
	}

	privateKey, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	return crypto.Sign(hash, privateKey)
}

// SignTxEIP155 implements accounts.Wallet, which allows the account to sign an ERC-20 transaction.
func (w *Wallet) SignTxEIP155(account eth.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	w.stateLock.RLock() // Comms have own mutex, this is for the state fields
	defer w.stateLock.RUnlock()

	// Make sure the requested account is contained within
	path, ok := w.paths[account.Address.Hex()]
	if !ok {
		return nil, eth.ErrUnknownAccount
	}

	privateKey, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	signer := types.NewEIP155Signer(chainID)
	// Sign the transaction and verify the sender to avoid hardware fault surprises
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return nil, err
	}

	sender, err := types.Sender(signer, signedTx)
	if err != nil {
		return nil, err
	}

	if sender != account.Address {
		return nil, fmt.Errorf("signer mismatch: expected %s, got %s", account.Address.Hex(), sender.Hex())
	}

	return signedTx, nil
}

// SignTx implements accounts.Wallet, which allows the account to sign an Ethereum transaction.
func (w *Wallet) SignTx(account tronAccount, tx *core.Transaction, chainID *big.Int) (*core.Transaction, error) {
	w.stateLock.RLock() // Comms have own mutex, this is for the state fields
	defer w.stateLock.RUnlock()

	// Make sure the requested account is contained within
	path, ok := w.paths[account.Address.String()]
	if !ok {
		return nil, eth.ErrUnknownAccount
	}

	privateKey, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	rawData, err := proto.Marshal(tx.GetRawData())
	if err != nil {
		return nil, err
	}

	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)

	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}

	tx.Signature = append(tx.Signature, signature)

	return tx, nil
}

// SignHashWithPassphrase implements accounts.Wallet, attempting
// to sign the given hash with the given account using the
// passphrase as extra authentication.
func (w *Wallet) SignHashWithPassphrase(account eth.Account, passphrase string, hash []byte) ([]byte, error) {
	return w.SignHash(account, hash)
}

// PrivateKey returns the ECDSA private key of the account.
func (w *Wallet) PrivateKey(account eth.Account) (*ecdsa.PrivateKey, error) {
	path, err := ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}

	return w.derivePrivateKey(path)
}

// PrivateKeyBytes returns the ECDSA private key in bytes format of the account.
func (w *Wallet) PrivateKeyBytes(account eth.Account) ([]byte, error) {
	privateKey, err := w.PrivateKey(account)
	if err != nil {
		return nil, err
	}

	return crypto.FromECDSA(privateKey), nil
}

// PrivateKeyHex return the ECDSA private key in hex string format of the account.
func (w *Wallet) PrivateKeyHex(account eth.Account) (string, error) {
	privateKeyBytes, err := w.PrivateKeyBytes(account)
	if err != nil {
		return "", err
	}

	return hexutil.Encode(privateKeyBytes)[2:], nil
}

// PublicKey returns the ECDSA public key of the account.
func (w *Wallet) PublicKey(account eth.Account) (*ecdsa.PublicKey, error) {
	path, err := ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}

	return w.derivePublicKey(path)
}

// PublicKeyBytes returns the ECDSA public key in bytes format of the account.
func (w *Wallet) PublicKeyBytes(account eth.Account) ([]byte, error) {
	publicKey, err := w.PublicKey(account)
	if err != nil {
		return nil, err
	}

	return crypto.FromECDSAPub(publicKey), nil
}

// PublicKeyHex return the ECDSA public key in hex string format of the account.
func (w *Wallet) PublicKeyHex(account eth.Account) (string, error) {
	publicKeyBytes, err := w.PublicKeyBytes(account)
	if err != nil {
		return "", err
	}

	return hexutil.Encode(publicKeyBytes)[4:], nil
}

// Address returns the address of the account.
func (w *Wallet) Address(account eth.Account) (common.Address, error) {
	publicKey, err := w.PublicKey(account)
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*publicKey), nil
}

// AddressBytes returns the address in bytes format of the account.
func (w *Wallet) AddressBytes(account eth.Account) ([]byte, error) {
	address, err := w.Address(account)
	if err != nil {
		return nil, err
	}
	return address.Bytes(), nil
}

// AddressHex returns the address in hex string format of the account.
func (w *Wallet) AddressHex(account eth.Account) (string, error) {
	address, err := w.Address(account)
	if err != nil {
		return "", err
	}
	return address.Hex(), nil
}

// Path return the derivation path of the account.
func (w *Wallet) Path(account eth.Account) (string, error) {
	return account.URL.Path, nil
}

// SignData signs keccak256(data). The mimetype parameter describes the type of data being signed
func (w *Wallet) SignData(account eth.Account, mimeType string, data []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if !w.Contains(account) {
		return nil, eth.ErrUnknownAccount
	}

	return w.SignHash(account, crypto.Keccak256(data))
}

// SignDataWithPassphrase signs keccak256(data). The mimetype parameter describes the type of data being signed
func (w *Wallet) SignDataWithPassphrase(account eth.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if !w.Contains(account) {
		return nil, eth.ErrUnknownAccount
	}

	return w.SignHashWithPassphrase(account, passphrase, crypto.Keccak256(data))
}

// SignText requests the wallet to sign the hash of a given piece of data, prefixed
// the needed details via SignHashWithPassphrase, or by other means (e.g. unlock
// the account in a keystore).
func (w *Wallet) SignText(account eth.Account, text []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if !w.Contains(account) {
		return nil, eth.ErrUnknownAccount
	}

	return w.SignHash(account, eth.TextHash(text))
}

// SignTextWithPassphrase implements accounts.Wallet, attempting to sign the
// given text (which is hashed) with the given account using passphrase as extra authentication.
func (w *Wallet) SignTextWithPassphrase(account eth.Account, passphrase string, text []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if !w.Contains(account) {
		return nil, eth.ErrUnknownAccount
	}

	return w.SignHashWithPassphrase(account, passphrase, eth.TextHash(text))
}

// ParseDerivationPath parses the derivation path in string format into []uint32
func ParseDerivationPath(path string) (eth.DerivationPath, error) {
	return eth.ParseDerivationPath(path)
}

// MustParseDerivationPath parses the derivation path in string format into
// []uint32 but will panic if it can't parse it.
func MustParseDerivationPath(path string) eth.DerivationPath {
	parsed, err := eth.ParseDerivationPath(path)
	if err != nil {
		panic(err)
	}

	return parsed
}

// NewMnemonic returns a randomly generated BIP-39 mnemonic using 128-256 bits of entropy.
func NewMnemonic(bits int) (string, error) {
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// NewMnemonicFromEntropy returns a BIP-39 mnemonic from entropy.
func NewMnemonicFromEntropy(entropy []byte) (string, error) {
	return bip39.NewMnemonic(entropy)
}

// NewEntropy returns a randomly generated entropy.
func NewEntropy(bits int) ([]byte, error) {
	return bip39.NewEntropy(bits)
}

// NewSeed returns a randomly generated BIP-39 seed.
func NewSeed() ([]byte, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	return b, err
}

// NewSeedFromMnemonic returns a BIP-39 seed based on a BIP-39 mnemonic.
func NewSeedFromMnemonic(mnemonic string) ([]byte, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	return bip39.NewSeedWithErrorChecking(mnemonic, "")
}

// DerivePrivateKey derives the private key of the derivation path.
func (w *Wallet) derivePrivateKey(path eth.DerivationPath) (*ecdsa.PrivateKey, error) {
	var err error
	key := w.masterKey
	for _, n := range path {
		if w.fixIssue172 && key.IsAffectedByIssue172() {
			key, err = key.Derive(n)
		} else {
			key, err = key.DeriveNonStandard(n)
		}
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := key.ECPrivKey()
	privateKeyECDSA := privateKey.ToECDSA()
	if err != nil {
		return nil, err
	}

	return privateKeyECDSA, nil
}

// DerivePublicKey derives the public key of the derivation path.
func (w *Wallet) derivePublicKey(path eth.DerivationPath) (*ecdsa.PublicKey, error) {
	privateKeyECDSA, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key")
	}

	return publicKeyECDSA, nil
}

// DeriveAddress derives the account address of the derivation path.
func (w *Wallet) deriveAddress(path eth.DerivationPath) (interface{}, string, error) {
	publicKeyECDSA, err := w.derivePublicKey(path)
	if err != nil {
		return struct{}{}, "", err
	}

	coin, err := extractCoinType(path)
	if err != nil {
		return struct{}{}, "", err
	}

	switch coin {
	case "eth":
		return crypto.PubkeyToAddress(*publicKeyECDSA), "eth", nil
	case "tron":
		return tron.PubkeyToAddress(*publicKeyECDSA), "tron", nil
	default:
		return struct{}{}, "", errors.New("invalid coin type")
	}
}

func removeEthAccountAtIndex(accts []eth.Account, index int) []eth.Account {
	return append(accts[:index], accts[index+1:]...)
}

func removeTronAccountAtIndex(accts []tronAccount, index int) []tronAccount {
	return append(accts[:index], accts[index+1:]...)
}

func extractCoinType(path eth.DerivationPath) (string, error) {
	switch path[1] {
	case 0x800000C3:
		return TronCoin, nil
	case 0x8000003C:
		return EthereumCoin, nil
	default:
		return "", errors.New("invalid path")
	}
}
