package lamport

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/exp/slices"
)

type OneTimeAuthPassword [32]byte

type OneTimeAuthAlice struct {
	secret    OneTimeAuthPassword
	passwords []OneTimeAuthPassword
	offset    int
}

func NewOneTimeAuthAlice(n int) *OneTimeAuthAlice {
	secret := randHex()
	return &OneTimeAuthAlice{secret: secret, passwords: makePasswords(secret, n)}
}

func (alice *OneTimeAuthAlice) InitialPassword() OneTimeAuthPassword {
	return alice.passwords[0]
}

func (alice *OneTimeAuthAlice) NextPassword() (*OneTimeAuthPassword, error) {
	if alice.offset >= len(alice.passwords) {
		return nil, errors.New("all passwords used")
	}
	alice.offset += 1
	return &alice.passwords[alice.offset-1], nil
}

func makePasswords(secret OneTimeAuthPassword, n int) []OneTimeAuthPassword {
	passwords := make([]OneTimeAuthPassword, n)
	for i := 0; i < n; i++ {
		if i == 0 {
			passwords[i] = secret
			continue
		}
		passwords[i] = sha256.Sum256(passwords[i-1][:])
	}
	slices.Reverse(passwords)
	return passwords
}
