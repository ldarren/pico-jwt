const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const algoMap = {
	HS256: 'SHA256',
	HS384: 'SHA384',
	HS512: 'SHA512',
	RS256: 'RSA-SHA256',
	RS384: 'RSA-SHA384',
	RS512: 'RSA-SHA512',
}

function base64(str){
  return new Buffer(str).toString('base64')
}

function urlEscape(b64) {
  return b64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function urlUnescape(b64) {
    return b64.replace(/\-/g, '+').replace(/_/g, '/') + new Array(5 - b64.length % 4).join('=')
}

function sign(segments, alg, secret){
    const algName = algoMap[alg]
    if ('R' === alg.charAt(0)){
		const c = crypto.createSign(algName)
		c.write(segments[0])
		c.write('.')
		c.write(segments[1])
		c.end()
		return urlEscape(c.sign(secret, 'base64'))
	}else{
		const c = crypto.createHmac(algName, secret)
		c.update(segments[0])
		c.update('.')
		c.update(segments[1])
		return urlEscape(c.digest('base64'))
	}
}

function encode(data){
	return urlEscape(base64(JSON.stringify(data)))
}

function decode(data){
	try {
		return JSON.parse(Buffer.from(data, 'base64'))
	} catch (exp) {
		return console.error(exp)
	}
}

function readKey(key, cb){
	if (key && path.isAbsolute(key)) {
		return fs.readFile(key, 'utf8', cb)
	}
	cb(null, key)
}

function JWT(algo, secret, key){
	this.algo = algo
	this.addKeys(secret, key)
}

JWT.prototype = {
	addKeys(secret, key, cb){
		cb = cb || function(){}
		let i = 0
		readKey(secret, (err, privateKey) => {
			this.privateKey = privateKey
			if (2 === ++i) cb()
		})
		readKey(key, (err, publicKey) => {
			this.publicKey = publicKey
			if (2 === ++i) cb()
		})
	},
	create(payload, algo){
		const header = {
			typ: 'JWT',
			alg: algo || this.algo
		}
		const header64 = encode(header)
		const body64 = encode(payload)

		const segments = [header64, body64]
		segments.push(sign(segments, header.alg, this.privateKey))

		return segments.join('.')
	},
	read(jwt){
		const segments = jwt.split('.')

		return decode(segments[1])
	},
	verify(jwt){
		const segments = jwt.split('.')
		const header = decode(segments[0])
		if (!header) return false

		if ('JWT' !== header.typ) return console.error('wrong type', header.typ), false
		const algo = algoMap[header.alg]
		if (!algo) return console.error('algo not supported', header.alg), false

		if ('R' === header.alg.charAt(0)){
			const c = crypto.createVerify(algo)

			c.write(segments[0])
			c.write('.')
			c.write(segments[1])
			c.end()

			return c.verify(this.publicKey, Buffer.from(segments[2], 'base64'))
		} else {
			const c = crypto.createHmac(algo, this.privateKey)

			c.update(segments[0])
			c.update('.')
			c.update(segments[1])

			return urlEscape(c.digest('base64')) === segments[2]
		}
	}
}

module.exports = JWT
