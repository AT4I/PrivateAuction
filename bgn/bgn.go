package bgn

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/Nik-U/pbc"
)

// PolyEncodingParams specifies the parameters used for
// encoding a message as a polynomial
type PolyEncodingParams struct {
	PolyBase    int     // PolyCiphertext polynomial encoding base
	FPScaleBase int     // fixed point encoding scale base
	FPPrecision float64 // min error tolerance for fixed point encoding
}

// PublicKey is the BGN public key used for encryption
// as well as performing homomorphic operations on Ciphertexts
type PublicKey struct {
	G1 *pbc.Element // G1 elliptic curve group of order N
	P  *pbc.Element // generator of G1 ang GT
	Q  *pbc.Element // generator of subgroup H
	N  *big.Int     // order of the elliptic curve group

	MsgSpace      *big.Int     // valid message space for decryption (will not try to decrypt values beyond this range)
	Pairing       *pbc.Pairing // pairing between G1 and GT
	PairingParams string
	Deterministic bool // whether or not the homomorphic operations are deterministic

	PolyEncodingParams *PolyEncodingParams // message encoding parameters
	mu                 sync.Mutex          // mutex for parallel executions (pbc is not thread-safe)
}

// publicKeyWrapper is a wrapper for the BGN PublicKey struct
// for marshalling/unmarshalling purposes since pbc.Element does not export fields
type publicKeyWrapper struct {
	G1 []byte
	P  []byte
	Q  []byte
	N  *big.Int

	MsgSpace           *big.Int
	PairingParams      string
	Deterministic      bool
	PolyEncodingParams *PolyEncodingParams // message encoding parameters
}

// SecretKey used for decryption of PolyCiphertexts
type SecretKey struct {
	Key      *big.Int
	R        *big.Int // subgroup generated by Q = P^R
	PolyBase int
}

// NewKeyGen creates a new public/private key pair of size bits
func NewKeyGen(keyBits int, msgSpace *big.Int, polyBase int, fpScaleBase int, fpPrecision float64, deterministic bool) (*PublicKey, *SecretKey, error) {

	if keyBits < 16 {
		panic("key bits must be >= 16 bits in length")
	}

	if keyBits%2 != 0 {
		panic("key bits must be divisible by 2")
	}

	var q1 *big.Int    // random prime
	var q2 *big.Int    // secret key (random prime)
	var n *big.Int     // n = q1*q2
	var P *pbc.Element // first generator
	var Q *pbc.Element // second generator

	// generate a new random prime r
	q1, q2, err := newPrimeTuple(keyBits)
	if err != nil {
		return nil, nil, err
	}

	if q1.Cmp(msgSpace) < 0 || q2.Cmp(msgSpace) < 0 {
		panic("Message space is greater than the group order!")
	}

	// compute the product of the primes
	n = big.NewInt(0).Mul(q1, q2)
	params := pbc.GenerateA1(n)
	paramsString := params.String()

	if err != nil {
		return nil, nil, err
	}

	// create a new pairing with given params
	pairing := pbc.NewPairing(params)

	// generate the two multiplicative groups of
	// order n (using pbc pairing library)
	G1 := pairing.NewG1()

	// obtain l generated from the pbc library
	// is a "small" number s.t. p + 1 = l*n
	l, err := parseLFromPBCParams(params)

	// find P a generator for the subgroup of order q1
	P = findGenerator(G1, q1, q2, n)
	P.PowBig(P, big.NewInt(0).Mul(l, big.NewInt(4)))

	// choose random Q in G1
	Q = G1.NewFieldElement()
	R := newCryptoRandom(n)
	Q.PowBig(P, R)
	Q.PowBig(Q, q2)

	polyParams := &PolyEncodingParams{
		polyBase, fpScaleBase, fpPrecision,
	}

	// create public key with the generated groups
	pk := &PublicKey{G1, P, Q, n, msgSpace, pairing, paramsString, deterministic, polyParams, sync.Mutex{}}

	// create secret key
	sk := &SecretKey{q1, R, polyBase}

	if err != nil {
		panic("Couldn't generate key params!")
	}

	pk.computeEncodingTable()

	return pk, sk, err
}

// ComputeDecryptionPreprocessing computes necessary values
// for decrypting via discrete log
func ComputeDecryptionPreprocessing(pk *PublicKey, sk *SecretKey) {
	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)

	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)
}

func newPrimeTuple(bitLength int) (*big.Int, *big.Int, error) {

	q1, err := rand.Prime(rand.Reader, bitLength/2)

	if err != nil {
		return nil, nil, err
	}

	// generate a new random prime q (this will be the secret key)
	q2, err := rand.Prime(rand.Reader, bitLength/2)

	if err != nil {
		return nil, nil, err
	}

	return q1, q2, nil

}

func findGenerator(G1 *pbc.Element, q1, q2, n *big.Int) *pbc.Element {

	// since we're working in an elliptic curve,
	// a point P is a generator if and only if for all divisors d of n=q1*q2
	// dP =/= 0 and Pn = 0
	// https://crypto.stackexchange.com/questions/66678/how-to-find-the-generators-of-an-elliptic-curve

	id := G1.NewFieldElement()
	for {
		P := G1.Rand()
		test1 := G1.NewFieldElement()
		test1.PowBig(P, q1)

		test2 := G1.NewFieldElement()
		test2.PowBig(P, n)

		if test1.Equals(id) || !test2.Equals(id) {
			continue
		}

		return P
	}
}

// SetupDecryption generates the necessary values for decryption
func (pk *PublicKey) SetupDecryption(sk *SecretKey) {
	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)
}

// Decrypt uses the secret key to recover the encrypted value
// throws an error if decryption fails
func (sk *SecretKey) Decrypt(ct *Ciphertext, pk *PublicKey) (*big.Int, error) {
	return sk.decrypt(ct, pk, false)
}

// DecryptFailSafe returns zero if encryption fails rather than throwing an error
func (sk *SecretKey) DecryptFailSafe(ct *Ciphertext, pk *PublicKey) *big.Int {
	v, err := sk.decrypt(ct, pk, false)
	if err != nil {
		return big.NewInt(0)
	}
	return v
}

func (sk *SecretKey) decrypt(ct *Ciphertext, pk *PublicKey, failed bool) (*big.Int, error) {
	gsk := pk.G1.NewFieldElement()
	csk := ct.C.NewFieldElement()

	gsk.PowBig(pk.P, sk.Key)
	csk.PowBig(ct.C, sk.Key)

	// move to GT if decrypting L2 ciphertext
	if ct.L2 {
		gsk = pk.Pairing.NewGT().Pair(pk.P, pk.P)
		gsk.PowBig(gsk, sk.Key)
	}

	pt, err := pk.recoverMessage(gsk, csk, ct.L2)

	// if the decryption failed, then try decrypting
	// the inverse of the element as it encodes a negative value
	if err != nil && !failed {
		neg := pk.Neg(ct)
		dec, err := sk.decrypt(neg, pk, true)
		if err != nil {
			return nil, err
		}
		return big.NewInt(0).Mul(big.NewInt(-1), dec), nil
	}

	// failed to decrypt for some other reason
	if err != nil && failed {
		return nil, err
	}

	return pt, nil
}

// MultConst multiplies an encrypted value by a constant
func (pk *PublicKey) MultConst(c *Ciphertext, constant *big.Int) *Ciphertext {

	// handle the case of L1 and L2 ciphertext seperately
	if !c.L2 {
		res := c.C.NewFieldElement()
		res.PowBig(c.C, constant)

		if !pk.Deterministic {
			r := newCryptoRandom(pk.N)
			q := c.C.NewFieldElement()

			pk.mu.Lock()
			q.MulBig(pk.Q, r)
			pk.mu.Unlock()

			res.Mul(res, q)
		}
		return &Ciphertext{res, c.L2}
	}

	pk.mu.Lock()
	res := pk.Pairing.NewGT().NewFieldElement()
	pk.mu.Unlock()

	res.PowBig(c.C, constant)

	if !pk.Deterministic {
		r := newCryptoRandom(pk.N)

		pk.mu.Lock()
		pair := pk.Pairing.NewGT().NewFieldElement().Pair(pk.Q, pk.Q)
		pk.mu.Unlock()

		pair.PowBig(pair, r)
		res.Mul(res, pair)
	}

	return &Ciphertext{res, c.L2}
}

// Mult multiplies two encrypted values together, making the ciphertext level2
func (pk *PublicKey) Mult(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {

	pk.mu.Lock()
	res := pk.Pairing.NewGT().NewFieldElement()
	pk.mu.Unlock()

	res.Pair(ct1.C, ct2.C)

	if !pk.Deterministic {
		r := newCryptoRandom(pk.N)

		pk.mu.Lock()
		pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
		pk.mu.Unlock()

		pair.PowBig(pair, r)
		res.Mul(res, pair)
	}

	return &Ciphertext{res, true}
}

func (pk *PublicKey) makeL2(ct *Ciphertext) *Ciphertext {
	result := pk.Pairing.NewGT().NewFieldElement()
	result.Pair(ct.C, pk.EncryptDeterministic(big.NewInt(1)).C)

	return &Ciphertext{result, true}
}

// EncryptDeterministic returns a deterministic (non randomized) ciphertext
// of the value x
func (pk *PublicKey) EncryptDeterministic(x *big.Int) *Ciphertext {

	G := pk.G1.NewFieldElement()
	G.PowBig(pk.P, x)

	return &Ciphertext{C: G, L2: false}
}

// Encrypt returns a ciphertext encrypting x
func (pk *PublicKey) Encrypt(x *big.Int) *Ciphertext {
	r := newCryptoRandom(pk.N)
	return pk.EncryptWithRandomness(x, r)
}

// EncryptWithRandomness encrypts a value using provided randomness r
func (pk *PublicKey) EncryptWithRandomness(x *big.Int, r *big.Int) *Ciphertext {

	pk.mu.Lock()
	G := pk.G1.NewFieldElement()
	G.PowBig(pk.P, x)
	H := pk.G1.NewFieldElement()
	H.PowBig(pk.Q, r)
	C := pk.G1.NewFieldElement()
	pk.mu.Unlock()

	C.Mul(G, H)

	return &Ciphertext{C, false}
}

// RecoverMessage finds the discrete logarithm to recover and returns the value (if found)
// if the value is too large, an error is thrown
func (pk *PublicKey) recoverMessage(gsk *pbc.Element, csk *pbc.Element, l2 bool) (*big.Int, error) {

	zero := gsk.NewFieldElement()

	if zero.Equals(csk) {
		return big.NewInt(0), nil
	}

	m, err := pk.getDL(csk, gsk, l2)

	if err != nil {
		return nil, err
	}
	return m, nil

}

// Sub homomorphically subtracts two encrypted values and returns the result
func (pk *PublicKey) Sub(a *Ciphertext, b *Ciphertext) *Ciphertext {

	ct1 := a
	ct2 := b

	if a.L2 && !b.L2 {
		ct2 = pk.makeL2(b)
	}

	if !a.L2 && b.L2 {
		ct1 = pk.makeL2(a)
	}

	if ct1.L2 != ct2.L2 {
		panic("Attempting to add ciphertexts at different levels")
	}

	if ct1.L2 && ct2.L2 {
		pk.mu.Lock()
		result := pk.Pairing.NewGT().NewFieldElement()
		pk.mu.Unlock()

		result.Div(ct1.C, ct2.C)

		if pk.Deterministic {
			return &Ciphertext{result, true} // don't hide with randomness
		}

		r := newCryptoRandom(pk.N)

		pk.mu.Lock()
		pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
		pk.mu.Unlock()

		pair.PowBig(pair, r)
		result.Mul(result, pair)
		return &Ciphertext{result, false}

	}

	pk.mu.Lock()
	result := pk.G1.NewFieldElement()
	pk.mu.Unlock()

	result.Div(ct1.C, ct2.C)
	if pk.Deterministic {
		return &Ciphertext{C: result, L2: ct1.L2} // don't blind with randomness
	}

	rand := newCryptoRandom(pk.N)
	h1 := pk.G1.NewFieldElement()

	pk.mu.Lock()
	h1.PowBig(pk.Q, rand)
	pk.mu.Unlock()

	result.Mul(result, h1)
	return &Ciphertext{result, ct1.L2}
}

// Neg returns the additive inverse of the ciphertext
func (pk *PublicKey) Neg(c *Ciphertext) *Ciphertext {
	return pk.Sub(pk.encryptZero(), c)

}

// Add homomorphically adds two encrypted values and returns the result
func (pk *PublicKey) Add(a *Ciphertext, b *Ciphertext) *Ciphertext {

	ct1 := a
	ct2 := b

	if a.L2 && !b.L2 {
		ct2 = pk.makeL2(b)
	}

	if !a.L2 && b.L2 {
		ct1 = pk.makeL2(a)
	}

	if ct1.L2 && ct2.L2 {
		pk.mu.Lock()
		result := pk.Pairing.NewGT().NewFieldElement()
		pk.mu.Unlock()

		result.Mul(ct1.C, ct2.C)

		if pk.Deterministic {
			return &Ciphertext{result, ct1.L2}
		}

		r := newCryptoRandom(pk.N)

		pk.mu.Lock()
		pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
		pk.mu.Unlock()

		pair.PowBig(pair, r)

		result.Mul(result, pair)
		return &Ciphertext{result, ct1.L2}
	}

	pk.mu.Lock()
	result := pk.G1.NewFieldElement()
	pk.mu.Unlock()

	result.Mul(ct1.C, ct2.C)

	if pk.Deterministic {
		return &Ciphertext{result, ct1.L2}
	}

	rand := newCryptoRandom(pk.N)

	pk.mu.Lock()
	h1 := pk.G1.NewFieldElement()
	h1.PowBig(pk.Q, rand)
	pk.mu.Unlock()

	result.Mul(result, h1)
	return &Ciphertext{result, ct1.L2}
}

// NewCiphertextFromBytes generates a ciphertext from marshalled ciphertext.
// Requires the public key in order to ensure the correct pairing is used
func (pk *PublicKey) NewCiphertextFromBytes(data []byte) (*Ciphertext, error) {

	if len(data) == 0 {
		return nil, errors.New("no data provided")
	}

	w := ciphertextWrapper{}

	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&w); err != nil {
		return nil, err
	}

	var elem *pbc.Element
	if w.L2 {
		elem = pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
		elem.SetBytes(w.CBytes)
	} else {
		elem = pk.G1.NewFieldElement()
		elem.SetBytes(w.CBytes)
	}

	return NewCiphertext(elem, w.L2), nil

}

// NewPolyCiphertextFromBytes generates a poly ciphertext from marshalled poly ciphertext.
// Requires the public key in order to ensure the correct pairing is used
func (pk *PublicKey) NewPolyCiphertextFromBytes(data []byte) (*PolyCiphertext, error) {

	if len(data) == 0 {
		return nil, errors.New("no data provided")
	}

	w := polyCiphertextWrapper{}

	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&w); err != nil {
		return nil, err
	}

	coeffs := make([]*Ciphertext, 0)
	for _, coeffBytes := range w.CoeffBytes {

		var elem *pbc.Element
		if w.L2 {
			elem = pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
			elem.SetBytes(coeffBytes)
		} else {
			elem = pk.G1.NewFieldElement()
			elem.SetBytes(coeffBytes)
		}

		coeffs = append(coeffs, NewCiphertext(elem, w.L2))
	}

	return NewPolyCiphertext(coeffs, w.Degree, w.ScaleFactor, w.L2), nil
}

func (pk *PublicKey) encryptZero() *Ciphertext {
	return pk.EncryptDeterministic(big.NewInt(0))
}

// generates a new random number < max
func newCryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}

// TOTAL HACK to access the generated "l" in the C struct
// which the PBC library holds. The golang wrapper has
// no means of accessing the struct variable without
// knowing the exact memory mapping. Better approach
// would be to either compute l on the fly or figure
// out the memory mapping between the C struct and
// golang equivalent
func parseLFromPBCParams(params *pbc.Params) (*big.Int, error) {

	paramsStr := params.String()
	lStr := paramsStr[strings.Index(paramsStr, "l")+2 : len(paramsStr)-1]
	lInt, err := strconv.ParseInt(lStr, 10, 64)
	if err != nil {
		return nil, err
	}

	return big.NewInt(lInt), nil
}

// MarshalBinary is needed in order to encode/decode
// pbc.Element type since it has no exported fields
func (pk *PublicKey) MarshalBinary() ([]byte, error) {

	if pk.N == nil {
		return []byte(""), nil
	}

	// wrap struct
	w := publicKeyWrapper{
		G1:                 pk.G1.Bytes(),
		P:                  pk.P.Bytes(),
		Q:                  pk.Q.Bytes(),
		N:                  pk.N,
		MsgSpace:           pk.MsgSpace,
		Deterministic:      pk.Deterministic,
		PolyEncodingParams: pk.PolyEncodingParams,
		PairingParams:      pk.PairingParams,
	}

	// use default gob encoder
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary is needed in order to encode/decode
// pbc.Element type since it has no exported fields
func (pk *PublicKey) UnmarshalBinary(data []byte) error {

	if len(data) == 0 {
		return nil
	}

	w := publicKeyWrapper{}

	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&w); err != nil {
		return err
	}

	pairing, err := pbc.NewPairingFromString(w.PairingParams)
	if err != nil {
		fmt.Println(err)
		return err
	}

	G1 := pairing.NewG1()
	G1.SetBytes(w.G1)

	P := G1.NewFieldElement()
	P.SetBytes(w.P)

	Q := G1.NewFieldElement()
	Q.SetBytes(w.Q)

	pk.G1 = G1
	pk.P = P
	pk.Q = Q
	pk.N = w.N
	pk.MsgSpace = w.MsgSpace
	pk.Pairing = pairing
	pk.Deterministic = w.Deterministic
	pk.PolyEncodingParams = w.PolyEncodingParams
	pk.PairingParams = w.PairingParams

	return nil
}

