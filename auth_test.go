package lamport

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOneTimeAuth(t *testing.T) {
	t.Run("bob can verify alice, after receiving rounds count and initiate msg", func(t *testing.T) {
		rounds := 10_000
		alice := NewOneTimeAuthAlice(rounds)
		bob := NewOneTimeAuthBob(rounds, alice.InitialPassword())

		assert.Error(t, bob.Verify(randHex()), "bob should not accept random password")

		for i := 0; i < rounds; i++ {
			m_i, err := alice.NextPassword()
			assert.NoError(t, err, "alice should not return err when rounds not exceed")
			validationErr := bob.Verify(*m_i)
			assert.NoError(t, validationErr, "bob should not return err on verify alice's password")
		}

		m_i, err := alice.NextPassword()
		assert.Error(t, err, "alice should an error if somebody requires next round")
		assert.Nil(t, m_i)

		assert.Error(t, bob.Verify(randHex()), "bob should return an error if round offset exceeds")
	})

}
