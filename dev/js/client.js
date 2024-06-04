
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
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

async function dhkeKeyGen(){


  var clientKeyGen = await crypto.subtle.generateKey({
    "name": "ECDH",
    "namedCurve": "P-256"
  }, true, ['deriveBits',"deriveKey"]);
  
  // const keyPair = await window.crypto.subtle.generateKey(
  //   {
  //     name: "ECDH",
  //     namedCurve: "P-256",
  //   },
  //   true,
  //   ["deriveKey", "deriveBits"]
  // );
  
  console.log("Starship Public Key: ",clientKeyGen.publicKey)
  console.log("------------------------------------------")
  const exported = await crypto.subtle.exportKey("spki", clientKeyGen.publicKey);

  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = btoa(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

  console.log("SPKI Starship Public Key : ", pemExported )
  
}

dhkeKeyGen();
