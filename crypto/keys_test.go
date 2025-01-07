package crypto

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("True")

	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey, msg))

	// Invalid msg
	assert.False(t, sig.Verify(pubKey, []byte("false")))

	//Invalid pubKey
	invalidPrivKey := GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()
	assert.False(t, sig.Verify(invalidPubKey, msg))

}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}
