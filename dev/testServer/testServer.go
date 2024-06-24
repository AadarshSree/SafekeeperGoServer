package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	// "encoding/hex"
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
    Signature string `json:"signatureB64"`
    Desc string `json:"description"`
}

type ClientSecret struct {

    Ciphertext string `json:"ciphertext"`
    Iv string `json:"iv"`
}

// Global Var to Store Key

var DHKE_SHARED_KEY []byte


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

func storeSecret(w http.ResponseWriter, r *http.Request){

    //Only post request
    if r.Method != http.MethodPost {
        http.Error(w, "BAD REQUEST 400", http.StatusMethodNotAllowed)
        return
    }
    // fmt.Printf("[+] keyyy = %x",DHKE_SHARED_KEY)
    // if(DHKE_SHARED_KEY)


    if (len(DHKE_SHARED_KEY) == 0) {
        http.Error(w, "INVALID REQUEST 400 - KEY AGREEMENT FAILED", http.StatusInternalServerError)
        return
    }
    var clientSecret ClientSecret
    decoder := json.NewDecoder(r.Body)
    err := decoder.Decode(&clientSecret)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    fmt.Println("Ciphertext: ",clientSecret.Ciphertext)
    plaintextSecret,err := aesGcmDecrypt(clientSecret.Ciphertext,clientSecret.Iv, DHKE_SHARED_KEY)
    if err != nil {
        http.Error(w, "AES Error", http.StatusInternalServerError)
        return
    }

    fmt.Println(plaintextSecret,"\n")

    

    
    w.Write([]byte("OK"))

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
    DHKE_SHARED_KEY = sharedKeySHA256[:]
    fmt.Printf("[*] Shared Key (K_AB) = %x\n", DHKE_SHARED_KEY) // sha256 the key and use cuz?

    
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

    resp := ServerPublicKey{Ks: string(pemBytes), Signature: signPublicKey(string(pemBytes))  ,Desc: "Servers' Public Key for DHKE"}

	w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)


}



//Function to sign the DHKE PublicKey Kb for authenticated dhke

func signPublicKey(publicKeyStr string) (pubSignB64 string){

    // LET US NOW DEFINE THE PRIVATE KEY WE USE FOR SIGNING

    var strprivkey = "-----BEGIN EC PRIVATE KEY-----\n"+
    "MHcCAQEEIOiFY1s/QDHKuLEW4vP/nP/G2c3ycmUa5nvU0+lrIZswoAoGCCqGSM49"+
    "AwEHoUQDQgAEbB6DTE8c36n4kugRSl7t9fkwmHZval42WatGQpCW3DL75oRjMsRX"+
    "48x03WrduU1XYWcRmjAY5RePhquNkI4gRw==\n"+
    "-----END EC PRIVATE KEY-----"

    //END OF PRIVATE KEY

    private_key,err := DecodePrivateStr(strprivkey)
    if err != nil {
        fmt.Printf("Failed Decoding ECPRV %v", err)
    }

    // sha256 the key string 
    hash := sha256.New()
    hash.Write([]byte(publicKeyStr))
    hashBytes := hash.Sum(nil)

    r,s, err := ecdsa.Sign(rand.Reader, private_key, hashBytes) // sign 
    if err != nil {
        fmt.Printf("Failed to sign hash: %v", err)
    }

    // Concatenate r and s to get R|S cuz webcrypto doesnt support asn1 :(
    signature := append(r.Bytes(), s.Bytes()...)
    return base64.StdEncoding.EncodeToString(signature) // base 64 cuz it works over hexstr for some reason

}

// Helper functions to convert STR PEM format key to ecdsa.PrivateKey
func DecodePrivateStr(pemEncodedPriv string) (privateKey *ecdsa.PrivateKey, err error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))
    
    if blockPriv == nil {
        fmt.Println("Failed to decode PEM block containing private key")
    }
	x509EncodedPriv := blockPriv.Bytes

	privateKey, err = x509.ParseECPrivateKey(x509EncodedPriv)

	return
}

// DecodePublic public key
func DecodePublicStr(pemEncodedPub string) (publicKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
    if blockPub == nil {
        fmt.Println("Failed to decode PEM block containing private key")
    }
	x509EncodedPub := blockPub.Bytes

	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey = genericPublicKey.(*ecdsa.PublicKey)

	return
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


// Function to decrypt AES-GCM using KAB

func aesGcmDecrypt(ciphertextBase64 string, ivBase64 string, keyBA []byte) (string, error) {
	// Decode the base64 strings
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %v", err)
	}

	// Decode the hex string
	// key = keyBA

	// Create AES cipher block
	block, err := aes.NewCipher(keyBA)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %v", err)
	}

	// Create GCM mode of operation
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM mode: %v", err)
	}

	// Decrypt the ciphertext
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	// fmt.Printf("[+] Plaintext: %v\n",string(plaintext))
    return string(plaintext), nil
}

func main() {

	fmt.Println("Safekeeper Server Runing on Port 9021")


    // route handler
    http.HandleFunc("/safe", routeSafe)
    http.HandleFunc("/key", routeKey) // testing only key?kv=123

	//Route to diffie hellman key establishment
    http.HandleFunc("/dhke", dhke)
    
    //Route for password store
    //need to add checks later on forif key gen or not
    
    http.HandleFunc("/storeSecret", storeSecret)





    // Start the server on port
    http.ListenAndServe(":9021", nil)
}