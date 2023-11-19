# Go Lamport Signture/Authentication

## Overview
`go-lamport` is a Go implementation of the Lamport One-Time Signature scheme, a method of digital signature in cryptography. This project provides an efficient and secure way to generate and verify signatures in Go, leveraging the robustness of the Lamport signature algorithm.

## Features
- Generate Lamport key pairs (private and public keys).
- Sign messages using the Lamport one-time signature method.
- Verify signatures against the corresponding public key.
- Ensures high security by marking keys as disposed after one use.

## Installation
To use lib go-lamport, run the following command in your Go environment:

```bash
go get github.com/ssyrota/go-lamport
```

### Usage
Generating a Key Pair:
```go
import "github.com/ssyrota/go-lamport"

func main() {
    auth := lamport.NewOneTimeAuth()
    publicKey := auth.PublicKey()
    // Save the public key for later verification
}
```

Signing a Message:
```go
func main() {
    auth := lamport.NewOneTimeAuth()
    message := lamport.Message{...} // Your [32]byte message here
    signature, err := auth.Sign(message)
    if err != nil {
        // Handle error
    }
    // Use the signature
}
```

Verifying a Signature:
```go
func main() {
    publicKey := ... // Load the public key
    message := lamport.Message{...} // The message to verify
    signature := ... // The signature to verify

    isValid := lamport.OneTimeAuthVerify(message, signature, publicKey)
    if isValid {
        // Signature is valid
    } else {
        // Signature is invalid
    }
}
```

# Contributing
Contributions to go-lamport are welcome! Please read our contributing guidelines for details on how to submit contributions.

# License
This project is licensed under the MIT License.