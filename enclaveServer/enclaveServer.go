package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"

	// "encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"

    "github.com/gorilla/sessions"

	"github.com/edgelesssys/ego/enclave"

)


//Sessions
var sessionStore = sessions.NewCookieStore( []byte( "4d0a2ac8eba35caae67a591bd43ae06e6fe4744a1289ec6cbaa73ce7ea7cfb29" ) ) // testing key 

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
    SGX_QUOTE string `json:"SGX_QUOTE"`
    Desc string `json:"description"`
}

type ClientSecret struct {

    Ciphertext string `json:"ciphertext"`
    Iv string `json:"iv"`
}

// Global Var to Store Key replaced by session variable

// var DHKE_SHARED_KEY []byte


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

func ComputeHmacAndRespond(w http.ResponseWriter, r *http.Request){

    //Only post request
    if r.Method != http.MethodPost {
        http.Error(w, "BAD REQUEST 400", http.StatusMethodNotAllowed)
        return
    }
    // fmt.Printf("[+] keyyy = %x",DHKE_SHARED_KEY)
    // if(DHKE_SHARED_KEY)

    //session handle
    session, _ := sessionStore.Get(r, "clientSessionID")


    if dhkeKeyFromSession, ok := session.Values["dhke-key"]; ok {
        fmt.Printf("[!] DHKE KEY from SESSION -- %v \n",dhkeKeyFromSession)

    }else{
        fmt.Printf("[!] Session not found -- key agreement not done \n")
        http.Error(w, "INVALID REQUEST 400 - KEY AGREEMENT FAILED", http.StatusInternalServerError)
        return
    }

    dhkeKeyBytes, err := hex.DecodeString(session.Values["dhke-key"].(string))
        if err != nil {
            http.Error(w, "Failed to decode session key", http.StatusInternalServerError)
            return
        }
    
    


    if (len(dhkeKeyBytes) == 0) {
        http.Error(w, "INVALID REQUEST 400 - KEY AGREEMENT FAILED", http.StatusInternalServerError)
        return
    }
    var clientSecret ClientSecret
    decoder := json.NewDecoder(r.Body)
    if decoder.Decode(&clientSecret) != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    fmt.Println("Ciphertext: ",clientSecret.Ciphertext)
    plaintextSecret,err := aesGcmDecrypt(clientSecret.Ciphertext,clientSecret.Iv, dhkeKeyBytes)
    if err != nil {
        http.Error(w, "AES Error", http.StatusInternalServerError)
        return
    }

    fmt.Println(plaintextSecret,"\n")

    //now hmac

    sgx_hmac,err := SGX_HMAC(plaintextSecret)

    if err != nil {
        http.Error(w, "Hashing Error!", http.StatusInternalServerError)

    }

    fmt.Println("[*] HMAC: ",sgx_hmac)


    // w.Write([]byte("OK"))
    // response sgx_hmac

	response := map[string]string{
		"sgx_hmac": sgx_hmac,
	}

	// Set the response header to indicate JSON content
	w.Header().Set("Content-Type", "application/json")

	// Write the response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

}

// func enableCors(w *http.ResponseWriter) {
//     // (*w).Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:8080")
//     (*w).Header().Set("Access-Control-Allow-Origin", "*")
//     (*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
//     (*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
//     }

func dhke(w http.ResponseWriter, r *http.Request){

    // Enable CORS
    // enableCors(&w)

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
    // DHKE_SHARED_KEY = sharedKeySHA256[:]
    fmt.Printf("[*] Shared Key (K_AB) = %x\n", sharedKeySHA256[:]) // sha256 the key and use cuz?

    //SESSIONS 

    session, _ := sessionStore.Get(r, "clientSessionID")
    session.Values["dhke-key"] =  hex.EncodeToString(sharedKeySHA256[:])

    // Unset the Expires property to make it a session cookie
    session.Options = &sessions.Options{
        Path:   "*/*",
        // MaxAge: 0, // MaxAge 0 means no 'Expires' attribute and the cookie is a session cookie
        Secure:   true, // Ensure the cookie is only sent over HTTPS
        HttpOnly: true, // no js access
    }

    // session.Save(r, w)

    if session.Save(r, w) != nil {
        fmt.Println("{error} ERROR SAVING SESSION!!!")
        return
    }

    // session, _ = sessionStore.Get(r, "clientSessionID")

    // fmt.Println("[!] SESSSION clientSessionID.dhke-key = ",session.Values["dhke-key"])

    
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


    // GENERATE THE QUOTE HERE
    // THE QUOTE CONTAINS SHA256(K-pub-server)

    var hashOfKpubS = sha256.Sum256(pemBytes)

    //ENCLAVE ENTRY QUOTE

    sgx_report, err := enclave.GetRemoteReport(hashOfKpubS[:])
	if err != nil {
        
		fmt.Println(err)
        
	}


    resp := ServerPublicKey{Ks: string(pemBytes), Signature: signPublicKey(string(pemBytes))  , SGX_QUOTE: hex.EncodeToString(sgx_report)  ,Desc: "Servers' Public Key for DHKE"}

	w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)


}


func testSessions(w http.ResponseWriter, r *http.Request){


    session, _ := sessionStore.Get(r, "clientSessionID")

    // fmt.Println("[!] SESSSION clientSessionID.dhke-key = ",session.Values["dhke-key"])

    var responseMessage string

    if dhkeKey, ok := session.Values["dhke-key"]; ok {
        responseMessage = fmt.Sprintf("[!] SESSION clientSessionID.dhke-key = %v", dhkeKey)
    } else {
        responseMessage = "[!!] SESSION clientSessionID.dhke-key is not present"
    }

    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte(responseMessage))
   

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

// func to do hmac

func SGX_HMAC(secret string) (string, error) {
	//hardcoded the SGX key for now
	key, err := hex.DecodeString("8e415c7b5f8fd2432f17e1c5c17453519d9984042ba32ba9ae5c41f3b6db7404")
	if err != nil {
		return "", fmt.Errorf("failed to decode key: %v", err)
	}

	h := hmac.New(sha256.New, key)

	h.Write([]byte(secret))

	hmacValue := h.Sum(nil)

	// return hex string
	return hex.EncodeToString(hmacValue), nil
}

// Middleware function to handle CORS
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "https://keen.csrl.info") // geralt.csrl.info?
        //actually use domain name edit hosts file ipaddr domain map
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}

func main() {



    mux := http.NewServeMux()

    mux.Handle("/dhke", http.HandlerFunc(dhke))
    mux.Handle("/hmacSGX", http.HandlerFunc(ComputeHmacAndRespond))
    
    mux.Handle("/ts", http.HandlerFunc(testSessions))

    mux.Handle("/safe", http.HandlerFunc(routeSafe))
    mux.Handle("/key", http.HandlerFunc(routeKey))

    handler := corsMiddleware(mux)

	// Start the HTTP server
	fmt.Println("[*] Safekeeper Server Running on Port 8080 ...")
	err := http.ListenAndServe(":8080", handler)
	if(err != nil){
		fmt.Println(err)
	}
    // http.ListenAndServeTLS(":9021", "./.SSL_KEYS/cert.pem", "./.SSL_KEYS/key.pem", handler)



    // route handler

    // http.HandleFunc("/safe", routeSafe)
    // http.HandleFunc("/key", routeKey) // testing only key?kv=123

	// //Route to diffie hellman key establishment
    // http.HandleFunc("/dhke", dhke)
    
    // //Route for password store
    // //need to add checks later on forif key gen or not
    
    // http.HandleFunc("/storeSecret", storeSecret)


    // // Start the server on port
    // http.ListenAndServe(":9021", nil)
}
