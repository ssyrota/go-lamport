package lamport

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test(t *testing.T) {
	t.Run("signed message can be verified", func(t *testing.T) {
		auth := NewOneTimeSignature()
		message := MakeMessage()

		signature, err := auth.Sign(MakeMessage())

		assert.NoError(t, err, "on first time usage there should be no errors")
		assert.Equal(t, 256, len(signature))
		assert.True(t, OneTimeAuthVerify(message, *signature, auth.PublicKey()))
	})

	t.Run("malformed message is not verified", func(t *testing.T) {
		auth := NewOneTimeSignature()
		message := MakeMessage()

		signature, err := auth.Sign(message)

		assert.NoError(t, err, "on first time usage there should be no errors")
		assert.Equal(t, 256, len(signature))

		malformed := []byte(message[:])
		malformed[1] = byte(0)
		malformed[2] = byte(1)
		assert.False(t, OneTimeSignVerify([32]byte(malformed), *signature, auth.PublicKey()))
	})
}
