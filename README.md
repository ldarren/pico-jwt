# pico-jwt
A pico size JWT module

## Selling Points
- Small footprint (141 LOC)
- Simple and easy
- Zero dependencies

## Installation
`npm i pico-jwt`

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
})

// get header of jwt
const header = jwt.header(token)

// get payload of jwt
const payload = jwt.payload(token)

// verify jwy
if (!jwt.verify(token)) {
	console.log('failed')
}
```

## Debug Mode
Set `DEBUG` env variable to enable debug mode
