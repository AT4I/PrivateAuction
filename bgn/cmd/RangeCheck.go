package main

import (
	"fmt"
	"github.com/sachaservan/bgn"
	"log"
	"math/big"
	"math/rand"
	"time"
)

// following six to come as command line arguments : TBC-@Neha
const KEYBITS = 1024
const POLYBASE = 3
const MSGSPACE = 100000000 // message space for polynomial coefficients
const FPSCALEBASE = 3
const FPPREC = 0.0001
const DET = true // deterministic ops

type UserContext struct {
	bid  int
	pubK        *bgn.PublicKey
	secK        *bgn.SecretKey
	eBid        *bgn.Ciphertext
	partDecoded  *bgn.Ciphertext
}

func createPairwiseKey() (*bgn.PublicKey, *bgn.SecretKey, error) {
	start := time.Now()
	pk, sk, err := bgn.NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	elapsed := time.Since(start)
	log.Printf("Time for pairwise setup %s", elapsed)
	if err != nil {
		panic(err)
	}
	return pk, sk, err
}

const ITERATIONS = 1000  // @ TBC - @Neha take as argument

func main() {
	fmt.Println("Entering main()\n")
	// Initializing the seed using current time for random number generation.
	rand.Seed(time.Now().UnixNano())  // TBC @Neha take as argument
	
	bidders := make([]UserContext, 2)
	bidders[0].pubK, bidders[0].secK, _err = createPairwiseKey()
	if _err != nil { 
			panic(_err)
	}
	bgn.ComputeDecryptionPreprocessing(bidders[0].pubK, bidders[0].secK)

	bidders[1].pubK, bidders[1].secK, _err = createPairwiseKey()
	if _err != nil { 
			panic(_err)
	}
	bgn.ComputeDecryptionPreprocessing(bidders[1].pubK, bidders[1].secK)
			

	for i := 1; i < ITERATIONS; i = i + 1 {
		bidders[0].bid = rand.Intn(MAX_BID)
		bidders[1].bid = rand.Intn(MAX_BID)
		bidders[0].eBid = bidders[0].pubK.Encrypt(big.NewInt(int64(bidders[0].bid)))
		bidders[1].eBid = bidders[1].pubK.Encrypt(big.NewInt(int64(bidders[1].bid)))

		bidders[0].partDecoded := bidders[0].secK.DecryptFailSafe(bidders[0].eBid, bidders[0].pubK)
		bidders[1].partDecoded := bidders[1].secK.DecryptFailSafe(bidders[1].eBid, bidders[1].pubK)

		
		if(bidders[0].bid.Cmp(bidders[0].partDecoded) !=0 || 
		   	bidders[1].bid.Cmp(bidders[1].partDecoded) !=0 ) {
			fmt.Println("ERROR values are: ", bidders[0].bid, ", ",  bidders[1].bid,", ", bidders[0].partDecoded, ", ",  bidders[1].partDecoded,"\n")
		} else  if i % (ITERATIONS/10) == 0 {
			fmt.Println("values are: ", bidders[0].bid, ", ",  bidders[1].bid, ", ", bidders[0].partDecoded, ", ",  bidders[1].partDecoded,"\n")
		}

}
