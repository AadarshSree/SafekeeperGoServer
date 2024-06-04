package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// struct for json
type Response struct {
    Message string `json:"message"`
}

type KeyPair struct {

	KeyValue string `json:"keyValue"`
}

type ClientPublicKey struct {

	Ka string `json:"publicKey"`
}

type ServerPublicKey struct {

	Ks string `json:"publicKey"`
    Desc string `json:"description"`
}

func routeSafe(w http.ResponseWriter, r *http.Request) {
    // Create a new response object
    response := Response{Message: "Bonjour from Safekeeper server"}

    w.Header().Set("Content-Type", "application/json") //http headers

    json.NewEncoder(w).Encode(response)
}

func routeKey(w http.ResponseWriter, r *http.Request){

	fmt.Println("GET params were:", r.URL.Query())

	value := r.URL.Query().Get("kv")

	valueInt,err := strconv.Atoi(value)

	if(err != nil){
		//handle error
	}


	valueInt = valueInt * 10

	response := KeyPair{KeyValue: "KeyValue * 10 = "+strconv.Itoa(valueInt) }

	w.Header().Set("Content-Type", "application/json") 
    json.NewEncoder(w).Encode(response)

}


func dhke(w http.ResponseWriter, r *http.Request){


	if r.Method != http.MethodPost {
        http.Error(w, "BAD REQUEST 400", http.StatusMethodNotAllowed)
        return
    }

	var clientPubKey ClientPublicKey
	decoder := json.NewDecoder(r.Body)
    err := decoder.Decode(&clientPubKey)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    

    // Now let's convert PEM to *ecdh.PublicKey

    clientsPublicKey, err := pemToPubkey(clientPubKey.Ka)

    if(err!=nil){

        fmt.Printf("[!] Error in pemToPubKey: %v", err)
        return 
    }

    // Starting Diffie Hellman

    // we create servers ECDH thing
    serverDhke, _ := ecdh.P256().GenerateKey(rand.Reader)

    // Now let's compute the Kab

    sharedKey,_ := serverDhke.ECDH(clientsPublicKey)
    sharedKeySHA256 := sha256.Sum256(sharedKey)
    fmt.Printf("[*] Shared Key (K_AB) = %x\n", sharedKeySHA256) // sha256 the key and use cuz?

    
    // Now take servers public key convert to pem and send it in response

    // Marshal the public key to PKIX, ASN.1 DER form
    derBytes, err := x509.MarshalPKIXPublicKey(serverDhke.PublicKey())
    if err != nil {
        fmt.Printf("Failed to marshal servers public key: %v", err)
    }

    // Encode the DER bytes to PEM format
    pemBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: derBytes,
    }
    pemBytes := pem.EncodeToMemory(pemBlock)

    resp := ServerPublicKey{Ks: string(pemBytes), Desc: "Servers' Public Key for DHKE"}

	w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)


}

//helper function to convert PEM request (txt) to ECDH Public Key

func pemToPubkey(pemStr string) (*ecdh.PublicKey , error) {

    // var pemInput string = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER2bB7I8w6EZM7I8jI0HH4ceWIK6Z"+
    // "ASqkUZUDsbLrhjG0B3+xEUgRSekUmZOgqKrw/f0cpU2cZ9/FT97RNv1U+g==\n-----END PUBLIC KEY-----"


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
    
        // fmt.Printf("Public Key: %+v\n", parsedPubKey.Bytes())
        // fmt.Printf("Type: %T\n", (parsedKey))
        // fmt.Printf("BA: %x\n", (parsedKey))
    
        return parsedPubKey,nil
    
}

func main() {

	fmt.Println("Safekeeper Server Runing on Port 9021")


    // route handler
    http.HandleFunc("/safe", routeSafe)
    http.HandleFunc("/key", routeKey) // testing only key?kv=123

	//Route to diffie hellman key establishment
    http.HandleFunc("/dhke", dhke)




    // Start the server on port
    http.ListenAndServe(":9021", nil)
}