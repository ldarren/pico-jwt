const pico = require('pico-common/bin/pico-cli')
const { test } = pico.export('pico/test')
const JWT = require('./index')

const payload = {
	hello: 'world'
}
const secretKey = 'secret123'
const privateKey = __dirname + '/test.key'
const publicKey = __dirname + '/test.key.pub'

const hsJwt = new JWT('HS256', secretKey)
const rsJwt = new JWT('RS256')
const hsSig = 'pe233CdfCuOwFxw8O4nostPdxcvcIJxQpmprMYZmN0c'
const rsSig = 'bM5CbY3apiKHT-KQ3SfG5ZmX-8qsyBWURDCNnCUeJPq-zrKpOA4qOSoPbSkHGKmsjueRPWetOEib-d4lVZtwmi42SqaI6AtzsGuA37PxB5bGw9_1R0Wan-IYa_rnwnrt-kvv121AQzLwzIRmP4ss5fOnuV-ZO7nSpLCkRTekodUqcQ3eeu_YxkwEQEbqdBf970Dy7H0eZyT80MELbc0B2ga4UQfCen31yglv2bhEHQC0VqPCv-BNLz_IfXo-LO2fzNvOsMNae5Ag3mOKhOXEpJMlb-mY15ltGWWlhoBVpwJQRc1MiUkXhajzqg0B-_dq3j6Va8uci5UbKvkGM3hyoQ'

test('create JWT with HS256', cb => {
	cb(null, hsJwt.create(payload).includes(hsSig))
})
test('verify JWT with HS256', cb => {
	cb(null, hsJwt.verify(hsJwt.create(payload)))
})
test('read header from JWT', cb => {
	cb(null, 'JWT' === JWT.prototype.header(hsJwt.create(payload)).typ)
})
test('read payload from JWT', cb => {
	cb(null, payload.hello === JWT.prototype.payload(hsJwt.create(payload)).hello)
})

// wait for 
rsJwt.addKeys(privateKey, publicKey, () => {
	test('create JWT with RS256', cb => {
		cb(null, rsJwt.create(payload).includes(rsSig))
	})
	test('verify JWT with RS256', cb => {
		cb(null, rsJwt.verify(rsJwt.create(payload)))
	})
})
