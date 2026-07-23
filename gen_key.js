const forge = require('node-forge');

const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: 2 });
const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
// We need to format it as a single line JSON string or just handle newlines for .env
// Standard .env multiline handling can be tricky. Often base64 encoding is safer.
// Let's print Base64 encoded private key.

console.log('PRIVATE_KEY_BASE64=' + forge.util.encode64(privateKeyPem));
