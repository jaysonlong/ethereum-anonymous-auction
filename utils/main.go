package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
)

func main() {
	commandLineRingSig()
}

func commandLineRingSig() {
	var hexMsg, hexPriv, hexPub string
	fmt.Print("hexMsg:")
	fmt.Scan(&hexMsg)
	fmt.Print("hexPriv:")
	fmt.Scan(&hexPriv)
	fmt.Print("hexPub:")
	fmt.Scan(&hexPub)

	msg, _ := hex.DecodeString(hexMsg[2:])

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = globalCurve
	priv.D, _ = new(big.Int).SetString(hexPriv, 0)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(priv.D.Bytes())

	pubX, _ := new(big.Int).SetString(hexPub[2:66], 16)
	pubY, _ := new(big.Int).SetString(hexPub[66:], 16)
	pub := new(ecdsa.PublicKey)
	pub.X, pub.Y = pubX, pubY
	sig := RingSig(msg, priv, []*ecdsa.PublicKey{pub})
	sigBytesStr := encodeSignature(sig)
	fmt.Println(hex.EncodeToString(msg), sigBytesStr)
}

func test_ring_verify() {
	msg := []byte("hello")
	sigEncoded := "00000000000000000000000000000000000000000000000000000000000000066c1d33b5bcb333ec6346eb5a52b07b5ff9cb972ec09d06aa343d264acd7ec110797352e8409b05e4ab921c889fd49794b06084811c946342e8d79d1b804d3b6e8a9c6da61b13c3b44fd45575769c3eb0c499c87562e5830e28602a5d4c62574ae0f84b14f068b2aec108ed43fac17812b2a887ed0df0e35b0a1d0646ca358ffaa95a3e3439663a28c9702301e24c4dd80a173811b5e41b07e34ade00d4de87c12c614074a55f8ee8f9e9f02775528fc8945a8b68df602d8b9203a7aff3ffa00473bae056581f5c6899c82038134cb21d468dc5bcccdbc44122f667a2deb0d6bf495d09775c2054a500728787917ead4cb79e100a25cf42329555c921b302e0c2c2de61a6b1702af8d4f52ba86f0b218441f29b5391df75052a624bb60415933d9ad966a4585eed00c2ed666d2dd5fff989f7af98f4a3aeb98e2181dc5ae6fe4e438fb8964b8ea8d83209bbf6502d2806f744cbd025599d4fe3d1bccb274e97f602a9e96356f56754b6864f90916f048c70fc5e430bfb946ccc324272595ecd1554509ee885688ac711627ccb3e9c6928154a57698bc97e9d44b37c65731cccea2a61915d5621433e6253dae60fd2d4e89ed4de144d6211a026077e9b6d9b604bf8feccb6920080869e948dfe93e3940d89eeecc00ec474480ba952047d0c1b69ad273592510debb8bf98f0f643bd8072a267005f5f5405b84f38d2b14f78fe12416f7a59899d9c1a02f1866146282be5b428011eb6adec5519be7439ee276fb07aa741cbe65920ea30f7db89d67f1d8e545a4b659a8c52c7177aa6740f5e832ce44db76a0bf1671bc3f213b9373e8b5baadfb82b856151d49461f15fb1dd805c"
	sigBytes, _ := hex.DecodeString(sigEncoded)
	sig := decodeSignature(sigBytes)

	printSignature(msg, sig)

	isValid := VerifySig(msg, sig)
	fmt.Println("IsValid:", isValid)
}

func test_ring_sign_and_verify() {
	priv := generateKey()
	pubs := KeyGen(10)
	msg := []byte("hello")
	sig := RingSig(msg, priv, pubs)
	isValid := VerifySig(msg, sig)

	fmt.Println("IsValid:", isValid)
	fmt.Println("msg:", hex.EncodeToString(msg))
	fmt.Println("Signature:", encodeSignature(sig))
}
