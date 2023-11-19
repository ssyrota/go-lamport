package lamport

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

type OneTimeAuthBob struct {
	previous  OneTimeAuthPassword
	offset    int
	maxRounds int
}

func NewOneTimeAuthBob(maxRounds int, initialPassword OneTimeAuthPassword) *OneTimeAuthBob {
	return &OneTimeAuthBob{maxRounds: maxRounds, previous: initialPassword, offset: 0}
}

func (bob *OneTimeAuthBob) Verify(msg OneTimeAuthPassword) error {
	if bob.offset > bob.maxRounds-1 {
		return errors.New("max offset reached")
	}
	firstMsgMatches := bob.offset == 0 && bytes.Equal(bob.previous[:], msg[:])
	hash := sha256.Sum256(msg[:])
	nonFirstMsgMatches := bob.offset != 0 && bytes.Equal(bob.previous[:], hash[:])
	if firstMsgMatches || nonFirstMsgMatches {
		bob.offset += 1
		bob.previous = msg
		return nil
	}
	return errors.New("invalid password")
}
