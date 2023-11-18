package lamport

import (
	"strings"

	"github.com/biter777/countries"
)

func MakeMessage() [32]byte {
	var message strings.Builder
	totalBits := 0
	for totalBits < 256 {
		word := countries.UA
		message.WriteString(word.String())
		message.WriteString(" ")
		totalBits += len(word.String()) * 8 // Approximate bit count
		if totalBits >= 256 {
			break
		}
	}
	return [32]byte([]byte(message.String())[0:32])
}
