
console.log("Hello world Client")

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

async function dhkeKeyGen(){


  var clientKeyGen = await crypto.subtle.generateKey({
    "name": "ECDH",
    "namedCurve": "P-256"
  }, true, ['deriveBits',"deriveKey"]);
  
  
  // console.log("Clients Public Key: ",clientKeyGen.publicKey)
  console.log("------------------------------------------")
  const exported = await crypto.subtle.exportKey("spki", clientKeyGen.publicKey);

  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = btoa(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

  console.log("SPKI PEM Public Key : ", pemExported )

  // now let's send the generated key to the server

  const clientPubKey = { publicKey: pemExported}; 
  var responseFromServer = "";

  await fetch("http://localhost:9021/dhke", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(clientPubKey)
  })
  .then(response => response.json()) // Parse the JSON response
  .then(data => responseFromServer=data) // Handle the response data
  .catch(error => console.error(error)); 

  console.log("Response:",responseFromServer)

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

  console.log("Server Public Key: "+publicKey_server)

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

  console.log("Shared Key SHA256: ",hashHex)



}

//try to create key from server response key and use it for dhke
// delete this function latetr
async function responseToKey(){


  var clientKeyGen = await crypto.subtle.generateKey({
    "name": "ECDH",
    "namedCurve": "P-256"
  }, true, ['deriveBits',"deriveKey"]);

  var responseKeyPem = '-----BEGIN PUBLIC KEY-----\n' +
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+02xyXF9l1W9lOv5JSaOev3/NtLV\n' +
  't3KaeZ7874h25Dk8BtkcpvBg2btj1vhT7SEMoOpQeTSaWeLfTtVKl76hXg==\n' +
  '-----END PUBLIC KEY-----\n' // hardcoding it rn

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

  console.log("Server Public Key: "+publicKey_server)

  var sharedBits = await crypto.subtle.deriveBits({
    "name": "ECDH",
    "public": publicKey_server
  }, clientKeyGen.privateKey, 256);

  console.log("SHARED KEY: ",sharedBits)

  // now sha 256 it

  // Use crypto.subtle.digest to calculate the SHA-256 hash
  const hashBuffer = await crypto.subtle.digest("SHA-256", sharedBits);

  // Convert the ArrayBuffer to a hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  console.log("Shared Key SHA256: ",hashHex)


}

dhkeKeyGen();

