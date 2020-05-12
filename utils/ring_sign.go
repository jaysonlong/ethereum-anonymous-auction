package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type Signature struct {
	pubs []*ecdsa.PublicKey
	r    []*big.Int
	c0   *big.Int
}

var globalCurve = secp256k1.S256()

func generateKey() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(globalCurve, crand.Reader)
	if err != nil {
		panic(err)
	}

	return priv
}

func KeyGen(cnt int) []*ecdsa.PublicKey {
	pubs := make([]*ecdsa.PublicKey, cnt)

	for i := 0; i < cnt; i++ {
		pubs[i] = &generateKey().PublicKey
	}
	return pubs
}

func RingSig(msg []byte, priv *ecdsa.PrivateKey, pubs []*ecdsa.PublicKey) *Signature {
	pubs = append([]*ecdsa.PublicKey{&priv.PublicKey}, pubs...)
	cnt := len(pubs)
	if cnt == 0 {
		return nil
	}

	var (
		k                         = generateKey()
		c                         = make([]*big.Int, cnt)
		r                         = make([]*big.Int, cnt)
		rPriv                     = make([]*ecdsa.PrivateKey, cnt)
		hash                      [sha256.Size]byte
		X, RiX, RiY, tempX, tempY *big.Int
	)

	
	for i, pub := range pubs {
		if i == 0 {
			X = k.PublicKey.X
		} else {
			rPriv[i] = generateKey()
			r[i] = rPriv[i].D
			RiX, RiY = rPriv[i].PublicKey.X, rPriv[i].PublicKey.Y
			tempX, tempY = globalCurve.ScalarMult(pub.X, pub.Y, c[i].Bytes())
			X, _ = globalCurve.Add(RiX, RiY, tempX, tempY)
		}

		hash = sha256.Sum256(append(msg, X.Bytes()...))
		c[(i+1)%cnt] = new(big.Int).SetBytes(hash[:])
	}

	r[0] = new(big.Int).Mul(c[0], priv.D)
	r[0].Sub(k.D, r[0])
	r[0].Mod(r[0], globalCurve.Params().N)

	rand.Seed(time.Now().UnixNano())
	randIdx := rand.Intn(cnt)
	pubs = append(pubs[randIdx:], pubs[:randIdx]...)
	r = append(r[randIdx:], r[:randIdx]...)
	sig := &Signature{pubs, r, c[randIdx]}
	return sig
}

func VerifySig(msg []byte, sig *Signature) bool {
	var (
		ciNext                    = sig.c0
		hash                      [sha256.Size]byte
		X, RiX, RiY, tempX, tempY *big.Int
	)

	for i, pub := range sig.pubs {
		RiX, RiY = globalCurve.ScalarBaseMult(sig.r[i].Bytes())
		tempX, tempY = globalCurve.ScalarMult(pub.X, pub.Y, ciNext.Bytes())
		X, _ = globalCurve.Add(RiX, RiY, tempX, tempY)
		hash = sha256.Sum256(append(msg, X.Bytes()...))
		ciNext = new(big.Int).SetBytes(hash[:])
	}

	return ciNext.Cmp(sig.c0) == 0
}

func printSignature(msg []byte, sig *Signature) {
	var pubsArr = make([]*[2]string, len(sig.pubs))
	var rArr = make([]string, len(sig.pubs))
	for i, pub := range sig.pubs {
		pubsArr[i] = &[2]string{pub.X.String(), pub.Y.String()}
		rArr[i] = fmt.Sprint(sig.r[i])
	}

	pubsArrData, _ := json.Marshal(pubsArr)
	rData, _ := json.Marshal(rArr)

	fmt.Println("msg:", hex.EncodeToString(msg))
	fmt.Println("pubs:", string(pubsArrData))
	fmt.Println("r:", string(rData))
	fmt.Println("c0:", sig.c0.String())
}

func encodeSignature(sig *Signature) string {
	cnt := uint64(len(sig.r))
	sigBytes := make([]byte, (cnt*3+2)*32)

	var tempX, tempY, tempR []byte
	var xPos, yPos, rPos int

	for i, pub := range sig.pubs {
		tempX, tempY, tempR = pub.X.Bytes(), pub.Y.Bytes(), sig.r[i].Bytes()
		xPos, yPos, rPos = (i*3+1)*32+(32-len(tempX)), (i*3+2)*32+(32-len(tempY)), (i*3+3)*32+(32-len(tempR))
		copy(sigBytes[xPos:], tempX)
		copy(sigBytes[yPos:], tempY)
		copy(sigBytes[rPos:], tempR)
	}

	tempX = make([]byte, 32)
	binary.BigEndian.PutUint64(sigBytes[24:], cnt)
	tempX = sig.c0.Bytes()
	copy(sigBytes[len(sigBytes)-len(tempX):], tempX)

	return hex.EncodeToString(sigBytes)
}

func decodeSignature(sigBytes []byte) *Signature {
	cnt := int(binary.BigEndian.Uint64(sigBytes[24:32]))

	sig := new(Signature)
	sig.pubs = make([]*ecdsa.PublicKey, cnt)
	sig.r = make([]*big.Int, cnt)
	sig.c0 = new(big.Int).SetBytes(sigBytes[(cnt*3+1)*32:])

	var tempX, tempY, tempR *big.Int
	var xPos, yPos, rPos int

	for i := 0; i < cnt; i++ {
		xPos, yPos, rPos = (i*3+1)*32, (i*3+2)*32, (i*3+3)*32
		tempX = new(big.Int).SetBytes(sigBytes[xPos : xPos+32])
		tempY = new(big.Int).SetBytes(sigBytes[yPos : yPos+32])
		tempR = new(big.Int).SetBytes(sigBytes[rPos : rPos+32])
		sig.pubs[i] = &ecdsa.PublicKey{X: tempX, Y: tempY}
		sig.r[i] = tempR
	}

	return sig
}
