# pico-jwt
A pico size JWT module

## Why?
- Small footprint (184 LOC uncompressed)
- Simple and easy
- Minimum dependencies ([ecdsa-sig-formatter](https://github.com/Brightspace/node-ecdsa-sig-formatter))

## Installation
`npm i pico-jwt`

## Algorithms
This library supports most of the cryptographic algorithms for JWK:

alg Parameter Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA using SHA-256 hash algorithm
RS384 | RSASSA using SHA-384 hash algorithm
RS512 | RSASSA using SHA-512 hash algorithm
PS256 | RSASSA-PSS using SHA-256 hash algorithm
PS384 | RSASSA-PSS using SHA-384 hash algorithm
PS512 | RSASSA-PSS using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm

Please note that PSXXX only works on Node 6.12+ (excluding 7.x).

## Test
`npm test`

## Example
```javascript
// import module
const pJWT = require('pico-jwt')

// instantiate the module
const jwt = new pJWT('HS256', 'secretKey')

// or with private and public keys
// const jwt = new pJWT('RS256', 'privateKey', 'publicKey')

// or with private and public files (absolute path only)
// const jwt = new pJWT('RS256', 'privateKeyPath', 'publicKeyPath')

// or add key files asynchronous (absolute path only)
// jwt.addKeys('privateKeyPath', 'publicKeyPath', () => {
//	console.log('loaded')
//})

// create jwt with payload
const token = jwt.create({
	iss: 'pico',
	hello: 'world'
}, {
	kid: 'custom-header-key-id'
})

// get header of jwt
const header = jwt.header(token) // or pJWT.prototype.header(token)

// get payload of jwt
const payload = jwt.payload(token) // or pJWT.prototype.payload(token)

// verify jwt
if (!jwt.verify(token)) {
	console.log('failed')
}
```

## Debug Mode
Set `DEBUG` env variable to enable debug mode
