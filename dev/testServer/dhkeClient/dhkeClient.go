package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
)

type ClientPublicKey struct {

	Ka string `json:"publicKey"`
}

type ServerPublicKey struct {

	Ks string `json:"publicKey"`
    Desc string `json:"description"`
}

func main(){


	// Starting Diffie hellman 

	clientDhke, _ := ecdh.P256().GenerateKey(rand.Reader)

	// Marshal the public key to PKIX, ASN.1 DER form
    derBytes, err := x509.MarshalPKIXPublicKey(clientDhke.PublicKey())
    if err != nil {
        // fmt.Printf("Failed to marshal clients public key: %v", err)
		// os.Exit(1)
		log.Fatalf("Failed to marshal client public key: %v", err)
    }

    // Encode the DER bytes to PEM format
    pemBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: derBytes,
    }
    pemBytes := pem.EncodeToMemory(pemBlock)


    // publicKey := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER2bB7I8w6EZM7I8jI0HH4ceWIK6ZASqkUZUDsbLrhjG0B3+xEUgRSekUmZOgqKrw/f0cpU2cZ9/FT97RNv1U+g==\n-----END PUBLIC KEY-----"

	publicKey := string(pemBytes)

    reqBody := ClientPublicKey{Ka: publicKey} // encode client public key into json body for post

    jsonData, err := json.Marshal(reqBody)
    if err != nil {
        log.Fatalf("Error marshalling JSON: %v", err)
    }

	//post req to server
    resp, err := http.Post("http://localhost:9021/dhke", "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        log.Fatalf("Error making POST request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        log.Fatalf("Received non-200 response code: %d", resp.StatusCode)
    }

    var response ServerPublicKey //same struct as used by server
    err = json.NewDecoder(resp.Body).Decode(&response)
    if err != nil {
        log.Fatalf("Error decoding response: %v", err)
    }

    fmt.Printf("Response: %+v\n", response)
    // fmt.Printf("Public Key: %+s\n", response.Ks)

	// Now we need to convert the public key pem into ecdhPublicKey

	serversPublicKey, err := pemToPubkey(response.Ks)

    if(err!=nil){

        fmt.Printf("[!] Error in pemToPubKey: %v", err)
        return 
    }

	// Now let us use the key to gen dhke shared key

	sharedKey,_ := clientDhke.ECDH(serversPublicKey)
    sharedKeySHA256 := sha256.Sum256(sharedKey)
    fmt.Printf("\n[*] Shared Key (K_AB) = %x\n", sharedKeySHA256) // sha256 the key and use cuz?

}


//helper function to convert PEM request (txt) to ECDH Public Key

func pemToPubkey(pemStr string) (*ecdh.PublicKey , error) {

        var pemInput string = pemStr // rewrite bad rn

        // fmt.Println(pemInput)

        // Parse the PEM-encoded public key
        block, _ := pem.Decode([]byte(pemInput))

        if block == nil || block.Type != "PUBLIC KEY" {
            fmt.Println("Failed to decode PEM block containing public key")
            return nil, errors.New("failed to decode PEM block containing public key")
        }
    
        parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
        if err != nil {
            fmt.Printf("Failed to parse DER encoded public key: %v", err)
            return nil,err
        }
    
        parsedPubKey, err := (parsedKey.(*ecdsa.PublicKey)).ECDH()

        if( err != nil){
            fmt.Printf("Failed to convert to ECDH public key: %v", err)
            return nil,err
        }

    
        return parsedPubKey,nil
    
}