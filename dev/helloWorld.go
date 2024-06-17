package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	// "crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"log"
    b64 "encoding/base64"

	// "encoding/json"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

func main() {
    fmt.Println("Hello World 123")

    // dhke()
    // pemToPubkey()

    ecsign()
}

 // ECDSA signing for auth dhke ?

 func ecsign(){

    //gen key
    // signPrivateKey,_ := ecdsa.GenerateKey(elliptic.P256(),rand.Reader)


    // signPubKey := &signPrivateKey.PublicKey

    // fmt.Println("[*] --- ECDSA KEYS --- ")

    // prvStr,_ := EncodePrivate(signPrivateKey)
    // pubStr,_ := EncodePublic(signPubKey)

    // fmt.Printf("%v \n+-+-+-+-+-+\n%v",prvStr,pubStr)

    // // Compute the SHA-256 hash
    // hash := sha256.New()
    // hash.Write([]byte("FEINFEINFEIN"))
    // hashBytes := hash.Sum(nil)

    // _=hashBytes

    /*
            -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIOiFY1s/QDHKuLEW4vP/nP/G2c3ycmUa5nvU0+lrIZswoAoGCCqGSM49
        AwEHoUQDQgAEbB6DTE8c36n4kugRSl7t9fkwmHZval42WatGQpCW3DL75oRjMsRX
        48x03WrduU1XYWcRmjAY5RePhquNkI4gRw==
        -----END EC PRIVATE KEY-----
        
        +-+-+-+-+-+
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbB6DTE8c36n4kugRSl7t9fkwmHZv
        al42WatGQpCW3DL75oRjMsRX48x03WrduU1XYWcRmjAY5RePhquNkI4gRw==
        -----END PUBLIC KEY-----
    */

    var strprivkey = "-----BEGIN EC PRIVATE KEY-----\n"+
    "MHcCAQEEIOiFY1s/QDHKuLEW4vP/nP/G2c3ycmUa5nvU0+lrIZswoAoGCCqGSM49"+
    "AwEHoUQDQgAEbB6DTE8c36n4kugRSl7t9fkwmHZval42WatGQpCW3DL75oRjMsRX"+
    "48x03WrduU1XYWcRmjAY5RePhquNkI4gRw==\n"+
    "-----END EC PRIVATE KEY-----"

    var strpubkey = "-----BEGIN PUBLIC KEY-----\n"+
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbB6DTE8c36n4kugRSl7t9fkwmHZv" + 
    "al42WatGQpCW3DL75oRjMsRX48x03WrduU1XYWcRmjAY5RePhquNkI4gRw=="+
    "\n-----END PUBLIC KEY-----"

    private_key,err := DecodePrivateStr(strprivkey)
    if err != nil {
        log.Fatalf("FailDecode %v", err)
    }
    public_key, err := DecodePublicStr(strpubkey)
    if err != nil {
        log.Fatalf("Failed to Decode %v", err)
    }

    // fmt.Println(private_key,public_key)
    // Compute the SHA-256 hash
    hash := sha256.New()
    hash.Write([]byte("FEINFEINFEIN"))
    hashBytes := hash.Sum(nil)

    ////////////////////////////////////////////

    r,s, err := ecdsa.Sign(rand.Reader, private_key, hashBytes)
    if err != nil {
        log.Fatalf("Failed to sign hash: %v", err)
    }

    // signature := append(r.Bytes(), s.Bytes()...)
    // Concatenate r and s
    signature := append(r.Bytes(), s.Bytes()...)

    // Print the ASN.1 encoded signature
    fmt.Printf("R|S Signature base64: %v\n", b64.StdEncoding.EncodeToString(signature))
    fmt.Printf("R|S Signature hex: %v\n", hex.EncodeToString(signature))

    // Verify the signature with the public key using VerifyASN1
    valid := ecdsa.Verify(public_key, hashBytes[:], r,s)
    if valid {
        fmt.Println("Signature verification successful")
    } else {
        fmt.Println("Signature verification failed")
    }



 }


 // Str -> Key object
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

 // EncodePrivate private key
func EncodePrivate(privKey *ecdsa.PrivateKey) (key string, err error) {

    encoded, err := x509.MarshalECPrivateKey(privKey)

    if err != nil {
        return
    }
    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})

    key = string(pemEncoded)

    return
}

// EncodePublic public key
func EncodePublic(pubKey *ecdsa.PublicKey) (key string, err error) {

    encoded, err := x509.MarshalPKIXPublicKey(pubKey)

    if err != nil {
        return
    }
    pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

    

    key = string(pemEncodedPub)
    return
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

