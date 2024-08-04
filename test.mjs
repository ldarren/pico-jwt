// import module
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import pJWT from './index.js'

const dir = dirname(fileURLToPath(import.meta.url))

// instantiate the module
const jwt = new pJWT('RS256')

// add key files asynchronous (absolute path only)
jwt.addKeys(dir + '/test.key', dir + '/test.key.pub', () => {
	console.log('loaded')

	const rawHeader = {
		kid: 'custom-header-key-id'
	}
	const rawPayload = {
		iss: 'pico',
		aud: 'world'
	}

	// create jwt with payload
	const token = jwt.create(rawPayload, rawHeader)

	// get header of jwt
	const header = jwt.header(token) // or pJWT.prototype.header(token)
	console.log('jwt header extract:', rawHeader.kid === header.kid)

	// get payload of jwt
	const payload = jwt.payload(token) // or pJWT.prototype.payload(token)
	console.log('jwt payload extract:', rawPayload.aud === payload.aud)

	// verify jwt
	console.log('jwt validation:', jwt.verify(token))
})
