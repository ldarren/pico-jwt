const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const SEP = '.'
const TYP = 'JWT'

const debug = process.env.DEBUG ? console.error : () => {}

function readKey(key, cb){
	if (key && path.isAbsolute(key)) {
		return fs.readFile(key, 'utf8', cb)
	}
	cb(null, key)
}

function pos(jwt, index){
	switch(index){
	case 0: return -1
	case 1: return jwt.indexOf(SEP)
	case 2: return jwt.lastIndexOf(SEP)
	}
}

function cut(jwt, start, end){
	return jwt.substring(pos(jwt, start) + 1, pos(jwt, end))
}

function algoMap(alg) {
	switch (alg.substr(0, 2)) {
	case 'HS': return 'SHA' + alg.substr(2)
	case 'RS': return 'RSA-SHA' + alg.substr(2)
	}
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
    const algName = algoMap(alg)
    if ('R' === alg.charAt(0)){
		const c = crypto.createSign(algName)
		c.write(segments[0])
		c.write(SEP)
		c.write(segments[1])
		c.end()
		return urlEscape(c.sign(secret, 'base64'))
	}else{
		const c = crypto.createHmac(algName, secret)
		c.update(segments[0])
		c.update(SEP)
		c.update(segments[1])
		return urlEscape(c.digest('base64'))
	}
}

function encode(obj){
	return urlEscape(base64(JSON.stringify(obj)))
}

function decode(b64){
	try {
		return JSON.parse(Buffer.from(b64, 'base64'))
	} catch (exp) {
		return debug(exp)
	}
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
			typ: TYP,
			alg: algo || this.algo
		}
		const header64 = encode(header)
		const body64 = encode(payload)

		const segments = [header64, body64]
		segments.push(sign(segments, header.alg, this.privateKey))

		return segments.join(SEP)
	},
	header(jwt){
		return decode(cut(jwt, 0, 1))
	},
	payload(jwt){
		return decode(cut(jwt, 1, 2))
	},
	verify(jwt){
		const header = this.header(jwt)
		if (!header) return false

		if (TYP !== header.typ) return debug('wrong type', header.typ), false
		const algo = algoMap(header.alg)
		if (!algo) return debug('algo not supported', header.alg), false

		if ('R' === header.alg.charAt(0)){
			const c = crypto.createVerify(algo)

			c.write(cut(jwt, 0, 2))
			c.end()

			return c.verify(this.publicKey, Buffer.from(cut(jwt, 2), 'base64'))
		} else {
			const c = crypto.createHmac(algo, this.privateKey)

			c.update(cut(jwt, 0, 2))

			return urlEscape(c.digest('base64')) === cut(jwt, 2)
		}
	}
}

module.exports = JWT
