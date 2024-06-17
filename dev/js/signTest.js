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

async function signing(){

    // Convert the Public Key text to Object

    var pubKeyStr = "-----BEGIN PUBLIC KEY-----\n"+
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbB6DTE8c36n4kugRSl7t9fkwmHZv" + 
                    "al42WatGQpCW3DL75oRjMsRX48x03WrduU1XYWcRmjAY5RePhquNkI4gRw=="+
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

    console.log("Server Public Key: "+publicKey_server)

    // R|S Signature
    var serverSignatureHex = "2342bc7b3f22c116c834dc54be970e673d75d3d51ce8f45a6a05d97bc907ec2bdc28c1a7af77decdd40e7cd2f60efbde4a1ef5164dfcf4c5e107e9af397c50d7"
    var serverSignB64 = "TXj2pVCfhnbh42CyFXvviHYJ5TGTasas+1hki2xKn37DZf/fzdQj4eYUH6wZe/x+RBrsJ/jybswePudO6kOPHA=="
    // var serverSignB64 = "pU2zOBJ3XrPASTyUhm6QQ50WXRgh2ECOZ90V3tw4aIqYT4fZby/4LTz9WpXE9lhPHK8E6akqWSuA+2M7Eto3cA=="

    // Verify the signature
    const valid = await crypto.subtle.verify(
        {
            name: 'ECDSA',

            hash: { name: 'SHA-256' },
        },
        publicKey_server,
        str2ab(atob(serverSignB64)),
        str2ab("FEINFEINFEIN")
    );

    console.log('Signature valid:', valid);


}


signing();