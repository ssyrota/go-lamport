package lamport

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

type SignatureKey = [256][2][32]byte

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

type SignatureMessage [32]byte

func (msg *SignatureMessage) Hash() [32]byte {
	return sha256.Sum256(msg[:])
}

type OneTimeSignature struct {
	disposed   bool
	privateKey SignatureKey
	publicKey  SignatureKey
}

func (onetimeSign *OneTimeSignature) PublicKey() SignatureKey {
	return onetimeSign.publicKey
}
func OneTimeSignVerify(msg SignatureMessage, signature Signature, publicKey SignatureKey) bool {
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

func (onetimeSign *OneTimeSignature) Sign(msg SignatureMessage) (*Signature, error) {
	if onetimeSign.disposed {
		return nil, errors.New("private key already used")
	}
	onetimeSign.disposed = true

	sign := Signature{}
	hash := msg.Hash()
	for i := 0; i < 256; i++ {
		if hash[i/8]&(1<<(uint(i)%8)) != 0 {
			sign[i] = onetimeSign.privateKey[i][1]
		} else {
			sign[i] = onetimeSign.privateKey[i][0]
		}
	}
	return &sign, nil
}

func NewOneTimeSignature() *OneTimeSignature {
	pkey := makeSignaturePrivateKey()
	return &OneTimeSignature{
		privateKey: pkey,
		publicKey:  makeSignatirePublicKey(pkey),
	}
}

func makeSignatirePublicKey(privateKey SignatureKey) SignatureKey {
	publicKey := SignatureKey{}
	for i := 0; i < 256; i++ {
		publicKey[i][0] = sha256.Sum256(privateKey[i][0][:])
		publicKey[i][1] = sha256.Sum256(privateKey[i][1][:])
	}
	return publicKey
}

func makeSignaturePrivateKey() SignatureKey {
	keys := SignatureKey{}
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
