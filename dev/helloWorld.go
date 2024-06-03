package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"

	// "encoding/json"
	"encoding/pem"
	"fmt"
)

func main() {
    fmt.Println("Hello World 123")

    // dhke()
    pemToPubkey()
}

// DIFFIE HELLMAN!

// ~/project/SafekeeperGoServer/dev

func pemToPubkey() *ecdh.PublicKey {

//     var pemInput string = `-----BEGIN PUBLIC KEY-----
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER2bB7I8w6EZM7I8jI0HH4ceWIK6Z
// ASqkUZUDsbLrhjG0B3+xEUgRSekUmZOgqKrw/f0cpU2cZ9/FT97RNv1U+g==
// -----END PUBLIC KEY-----`

var pemInput string = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER2bB7I8w6EZM7I8jI0HH4ceWIK6Z"+
"ASqkUZUDsbLrhjG0B3+xEUgRSekUmZOgqKrw/f0cpU2cZ9/FT97RNv1U+g==\n-----END PUBLIC KEY-----"

    fmt.Println(pemInput)
    // Parse the PEM-encoded public key
    block, _ := pem.Decode([]byte(pemInput))
    if block == nil || block.Type != "PUBLIC KEY" {
        fmt.Println("Failed to decode PEM block containing public key")
    }

    parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        fmt.Println("Failed to parse DER encoded public key: %v", err)
    }

    parsedPubKey, err := (parsedKey.(*ecdsa.PublicKey)).ECDH()
    

    fmt.Printf("Public Key: %+v\n", parsedPubKey.Bytes())
    fmt.Printf("Type: %T\n", (parsedKey))
    fmt.Printf("BA: %x\n", (parsedKey))

    return parsedPubKey


}

func dhke(){


    alice, _ := ecdh.P256().GenerateKey(rand.Reader)
    bob, _ := ecdh.P256().GenerateKey(rand.Reader)

    alicePubkey := alice.PublicKey() // func (k *ecdh.PrivateKey) PublicKey() *ecdh.PublicKey

    fmt.Printf("[*] PubKey = %x\n",alicePubkey.Bytes())
    
    // Marshal the public key to PKIX, ASN.1 DER form
    derBytes, err := x509.MarshalPKIXPublicKey(alicePubkey)
    if err != nil {
        fmt.Printf("Failed to marshal public key: %v", err)
    }

    // Encode the DER bytes to PEM format
    pemBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: derBytes,
    }
    pemBytes := pem.EncodeToMemory(pemBlock)

    // fmt.Printf("PEM DE = %x || %s",derBytes,string(derBytes[:]))

    // Print the PEM-encoded public key
    fmt.Printf("Public Key:\n%s\n", pemBytes)

    

    fmt.Println("------------------------------")

    shared, _ := bob.ECDH(alicePubkey)
    bobShared := sha256.Sum256(shared)
    fmt.Printf("Shared key (Bob)  %x\n", shared)
    fmt.Printf("Shared key SHA256 (Bob) %x\n", bobShared)

    bobPubkey := bob.PublicKey()

    shared, _ = alice.ECDH(bobPubkey)
    aliceShared := sha256.Sum256(shared)
    fmt.Printf("Shared key (Alice)  %x\n", shared)
    fmt.Printf("Shared key SHA256 (Alice)  %x\n", aliceShared)


}

