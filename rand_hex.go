package lamport

import "crypto/rand"

func randHex() [32]byte {
	bytes := [32]byte{}
	rand.Read(bytes[:])
	return bytes
}
