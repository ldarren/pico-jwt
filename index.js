const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const ecdsa = require('ecdsa-sig-formatter')

const SEP = '.'
const TYP = 'JWT'
const FMT = 'base64'

const debug = process.env.DEBUG ? console.error : () => {}

function readKey(key, cb){
	if (key && key.charAt && path.isAbsolute(key)) {
		return fs.readFile(key, cb)
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
	case 'ES':
	case 'PS':
	case 'RS': return 'RSA-SHA' + alg.substr(2)
	}
}

function base64(str){
	return Buffer.from(str).toString(FMT)
}

function urlEscape(b64) {
	return b64
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '')
}

function _urlUnescape(b64) {
	return b64.replace(/-/g, '+').replace(/_/g, '/') + new Array(5 - b64.length % 4).join('=')
}

function sign(segments, alg, key){
	const algo = algoMap(alg)
	let c
	switch(alg.charAt(0)){
	case 'H':
		c = crypto.createHmac(algo, key)
		c.update(segments[0])
		c.update(SEP)
		c.update(segments[1])
		return urlEscape(c.digest(FMT))
	case 'P':
		c = crypto.createSign(algo)
		c.write(segments[0])
		c.write(SEP)
		c.write(segments[1])
		c.end()
		return urlEscape(c.sign({
			key,
			padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
			saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
		}, FMT))
	case 'E':
		c = crypto.createSign(algo)
		c.write(segments[0])
		c.write(SEP)
		c.write(segments[1])
		c.end()
		return ecdsa.derToJose(urlEscape(c.sign(key, FMT)), alg)
	default:
		c = crypto.createSign(algo)
		c.write(segments[0])
		c.write(SEP)
		c.write(segments[1])
		c.end()
		return urlEscape(c.sign(key, FMT))
	}
}

function verify(headpay, sig, alg, key){
	const algo = algoMap(alg)
	if (!algo) return debug('algo not supported', alg), false

	let c
	switch(alg.charAt(0)){
	case 'H':
		c = crypto.createHmac(algo, key)
		c.update(headpay)

		return urlEscape(c.digest(FMT)) === sig
	case 'P':
		c = crypto.createVerify(algo)
		c.write(headpay)
		c.end()

		return c.verify({
			key,
			padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
			saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
		}, Buffer.from(sig, FMT))
	case 'E':
		sig = ecdsa.joseToDer(sig, alg)
		// fall through
	default:
		c = crypto.createVerify(algo)
		c.write(headpay)
		c.end()
		return c.verify(key, Buffer.from(sig, FMT))
	}
}

function encode(obj){
	return urlEscape(base64(JSON.stringify(obj)))
}

function decode(b64){
	try {
		return JSON.parse(Buffer.from(b64, FMT))
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
	create(payload, header = {}){
		const h = Object.assign({
			typ: TYP,
			alg: this.algo
		}, header)
		const header64 = encode(h)
		const body64 = encode(payload)

		const segments = [header64, body64]
		segments.push(sign(segments, h.alg, this.privateKey))

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
		if (!header) return debug('no header'), false

		if (header.typ && TYP !== header.typ) return debug('wrong type', header.typ), false

		return verify(cut(jwt, 0, 2), cut(jwt, 2), header.alg, this.publicKey || this.privateKey)
	}
}

module.exports = JWT
