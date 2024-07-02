
console.log("Hello world Client")

let DHKE_SHARED_KEY = ""

// Send POST Request

// const data = { publicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER2bB7I8w6EZM7I8jI0HH4ceWIK6ZASqkUZUDsbLrhjG0B3+xEUgRSekUmZOgqKrw/f0cpU2cZ9/FT97RNv1U+g==\n-----END PUBLIC KEY-----"}; 

// fetch("http://localhost:9021/dhke", {
//   method: "POST",
//   headers: { "Content-Type": "application/json" },
//   body: JSON.stringify(data)
// })
// .then(response => response.json()) // Parse the JSON response
// .then(data => console.log(data)) // Handle the response data
// .catch(error => console.error(error)); 


// web crypto P-256

//below are helper functions for str<->arraybuffer
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

// fn to verify the signature received in the response
async function verifyKeySignature(dhkeKey, dhkeSignature) {

  try {

    // Convert the Public Key text to Object

    var pubKeyStr = "-----BEGIN PUBLIC KEY-----\n" +
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbB6DTE8c36n4kugRSl7t9fkwmHZv" +
      "al42WatGQpCW3DL75oRjMsRX48x03WrduU1XYWcRmjAY5RePhquNkI4gRw==" +
      "\n-----END PUBLIC KEY-----"

    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pubKeyStr.substring(
      pemHeader.length,
      pubKeyStr.length - pemFooter.length - 1,
    ).trim();

    // base64 decode the string to get the binary data
    const binaryDerString = atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    const publicKey_server = await crypto.subtle.importKey(
      "spki",
      binaryDer,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ['verify']
    );

    console.log("Server Public Key: " + publicKey_server)

    // R|S Signature
    // Verify the signature
    const valid = await crypto.subtle.verify(
      {
        name: 'ECDSA',

        hash: { name: 'SHA-256' },
      },
      publicKey_server,
      str2ab(atob(dhkeSignature)),
      str2ab(dhkeKey)
    );

    console.log('Signature valid:', valid);

    return valid

  }
  catch (errr) {
    console.error(errr)
    return false
  }


}

async function dhkeKeyGen() {


  var clientKeyGen = await crypto.subtle.generateKey({
    "name": "ECDH",
    "namedCurve": "P-256"
  }, true, ['deriveBits', "deriveKey"]);


  // console.log("Clients Public Key: ",clientKeyGen.publicKey)
  console.log("------------------------------------------")
  const exported = await crypto.subtle.exportKey("spki", clientKeyGen.publicKey);

  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = btoa(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

  console.log("SPKI PEM Public Key : ", pemExported)

  // now let's send the generated key to the server

  const clientPubKey = { publicKey: pemExported };
  var responseFromServer = {};

  await fetch("http://localhost:9021/dhke", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(clientPubKey)
  })
    .then(response => response.json()) // Parse the JSON response
    .then(data => responseFromServer = data) // Handle the response data
    .catch(error => console.error(error));

  console.log("Response:", responseFromServer)

  // NOW Handle the response from server

  var responseKeyPem = responseFromServer.publicKey

  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = responseKeyPem.substring(
    pemHeader.length,
    responseKeyPem.length - pemFooter.length - 1,
  );
  // base64 decode the string to get the binary data
  const binaryDerString = atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  const publicKey_server = await crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    []
  );

  console.log("Server Public Key: " + publicKey_server)

  var sharedBits = await crypto.subtle.deriveBits({
    "name": "ECDH",
    "public": publicKey_server
  }, clientKeyGen.privateKey, 256);

  // console.log("SHARED KEY: ",sharedBits)

  // now sha 256 it

  // Use crypto.subtle.digest to calculate the SHA-256 hash
  const hashBuffer = await crypto.subtle.digest("SHA-256", sharedBits);

  // Convert the ArrayBuffer to a hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  console.log("Shared Key SHA256: ", hashHex)
  DHKE_SHARED_KEY = hashHex

  // Ok now let's verify the signature recieved in the response

  signValid = await verifyKeySignature(responseFromServer.publicKey, responseFromServer.signatureB64)

  if (signValid == true)
    console.log("\n[*] Signature Valid, Server Authenticated Key Exchange!")
  else {

    console.log("\n[!] KEY SIGNATURE NOT VALID! Cannot authenticate the server!")
    return
  }

  //AES?



}

//helper func
function ab2b64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

//AES ENC func

async function secretAesEncryption(key_hex_str, passwd) {

  console.log("[+] AES-256 GCM Encryption ")
  let key_buffer = new Uint8Array(key_hex_str.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  // console.log(key_buffer.length)

  const key_object = await crypto.subtle.importKey(
    "raw",
    key_buffer,
    {
      name: "AES-GCM",
    },
    true,
    ["encrypt", "decrypt"]
  );

  let iv = crypto.getRandomValues(new Uint8Array(12));

  const encoder = new TextEncoder();
  const encodedData = encoder.encode(passwd);

  const encryptedData = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key_object,
    encodedData
  );

  const encrypted_json = { "ciphertext": ab2b64(encryptedData), "iv": ab2b64(iv) };

  console.log(encrypted_json)

  return encrypted_json

}

const snooze = ms => new Promise(resolve => setTimeout(resolve, ms));


async function mainFunction() {

  await dhkeKeyGen();

  // after DHKE GEN

  // await snooze(2000)

  let userPassword = "hahaha123456789$";

  console.log(DHKE_SHARED_KEY)
  if (DHKE_SHARED_KEY != "") {


    encrypted_json = await secretAesEncryption(DHKE_SHARED_KEY, userPassword)

    // post req to server sending the ENC passwd
    console.log(encrypted_json)
    // await fetch("http://localhost:9021/storeSecret", {
    //   method: "POST",
    //   headers: { "Content-Type": "application/json" },
    //   body: JSON.stringify(encrypted_json)
    // })
    //   .then(response => console.log(response)) // Parse the JSON response
    //   .then(data => data) // Handle the response data
    //   .catch(error => console.error(error));

    try {
      const response = await fetch('http://localhost:9021/storeSecret', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(encrypted_json)
      });
  
      if (!response.ok) {
        throw new Error('BAD Server Response: ' + response.statusText);
      }
  
      const data = await response;  // Assuming the server responds with JSON
      console.log('Success:', data);
    } catch (error) {
      console.error('Error:', error);
    }

    
    console.log("+-+-+-+-+-+-+-+")

  } else {
    console.error("[!] DHKE SHARED KEY NOT SET")
  }

}


mainFunction();

