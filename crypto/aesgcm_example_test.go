package crypto_test

import (
	"bytes"
	"fmt"

	"github.com/glincker/theauth-go/crypto"
)

// ExampleEncrypt shows a round trip with a 32 byte key. The output of
// Encrypt is the random 12 byte nonce concatenated with the ciphertext
// and the GCM auth tag.
func ExampleEncrypt() {
	key := bytes.Repeat([]byte{0x42}, crypto.AESKeyLen)
	plaintext := []byte("hello, theauth")

	ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		panic(err)
	}
	got, err := crypto.Decrypt(key, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(got))
	// Output: hello, theauth
}
