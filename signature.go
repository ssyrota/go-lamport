package lamport

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

type Key = [256][2][32]byte

type Signature [256][32]byte

func (sign *Signature) Matches(pretender Signature) bool {
	for i, signPart := range sign {
		hashed := sha256.Sum256(pretender[i][:])
		for j, signByte := range signPart {
			if signByte != hashed[j] {
				return false
			}
		}
	}
	return true
}

type Message [32]byte

func (msg *Message) Hash() [32]byte {
	return sha256.Sum256(msg[:])
}

type OneTimeAuth struct {
	disposed   bool
	privateKey Key
	publicKey  Key
}

func (onetimeAuth *OneTimeAuth) PublicKey() Key {
	return onetimeAuth.publicKey
}
func OneTimeAuthVerify(msg Message, signature Signature, publicKey Key) bool {
	verify := Signature{}
	hash := msg.Hash()
	for i := 0; i < 256; i++ {
		if hash[i/8]&(1<<(uint(i)%8)) != 0 {
			verify[i] = publicKey[i][1]
		} else {
			verify[i] = publicKey[i][0]
		}
	}
	return verify.Matches(signature)
}

func (onetimeAuth *OneTimeAuth) Sign(msg Message) (*Signature, error) {
	if onetimeAuth.disposed {
		return nil, errors.New("private key already used")
	}
	onetimeAuth.disposed = true

	sign := Signature{}
	hash := msg.Hash()
	for i := 0; i < 256; i++ {
		if hash[i/8]&(1<<(uint(i)%8)) != 0 {
			sign[i] = onetimeAuth.privateKey[i][1]
		} else {
			sign[i] = onetimeAuth.privateKey[i][0]
		}
	}
	return &sign, nil
}

func NewOneTimeAuth() *OneTimeAuth {
	pkey := makePrivateKey()
	return &OneTimeAuth{
		privateKey: pkey,
		publicKey:  makePublicKey(pkey),
	}
}

func makePublicKey(privateKey Key) Key {
	publicKey := Key{}
	for i := 0; i < 256; i++ {
		publicKey[i][0] = sha256.Sum256(privateKey[i][0][:])
		publicKey[i][1] = sha256.Sum256(privateKey[i][1][:])
	}
	return publicKey
}

func makePrivateKey() Key {
	keys := Key{}
	for i := 0; i < 256; i++ {
		keys[i][0] = randHex()
		keys[i][1] = randHex()
	}
	return keys
}

func randHex() [32]byte {
	bytes := [32]byte{}
	rand.Read(bytes[:])
	return bytes
}
