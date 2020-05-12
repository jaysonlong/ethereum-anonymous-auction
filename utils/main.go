package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
)

func main() {
	commandLineRingSig()
}

func commandLineRingSig() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("input hexMsg:")
	hexMsg := ReadLine(reader)
	fmt.Print("input hexPriv:")
	hexPriv := ReadLine(reader)
	fmt.Print("input hexPubs:")
	hexPubs := ReadLine(reader)

	msg, _ := hex.DecodeString(hexMsg[2:])

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = globalCurve
	priv.D, _ = new(big.Int).SetString(hexPriv, 0)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(priv.D.Bytes())

	hexPubsArr := strings.Split(hexPubs, ",")
	pubs := make([]*ecdsa.PublicKey, len(hexPubsArr))
	for i, hexPub := range hexPubsArr {
		pubX, _ := new(big.Int).SetString(hexPub[2:66], 16)
		pubY, _ := new(big.Int).SetString(hexPub[66:], 16)
		pub := new(ecdsa.PublicKey)
		pub.X, pub.Y = pubX, pubY
		pubs[i] = pub
	}

	sig := RingSig(msg, priv, pubs)
	fmt.Println("\nmsgHex:", hex.EncodeToString(msg))
	fmt.Println("\nsignatureHex", encodeSignature(sig))
}

func ReadLine(reader *bufio.Reader) string {
	line, _, _ := reader.ReadLine()
	return string(line)
}
