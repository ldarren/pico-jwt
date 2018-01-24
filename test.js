const pico = require('pico-common/bin/pico-cli')
const ensure = pico.export('pico/test').ensure
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

ensure('create JWT with HS256', cb => {
	cb(null, hsJwt.create(payload).includes(hsSig))
})
ensure('verify JWT with HS256', cb => {
	cb(null, hsJwt.verify(hsJwt.create(payload)))
})
ensure('read header from JWT', cb => {
	cb(null, 'JWT' === hsJwt.header(hsJwt.create(payload)).typ)
})
ensure('read payload from JWT', cb => {
	cb(null, payload.hello === hsJwt.payload(hsJwt.create(payload)).hello)
})

// wait for 
rsJwt.addKeys(privateKey, publicKey, () => {
	ensure('create JWT with RS256', cb => {
		cb(null, rsJwt.create(payload).includes(rsSig))
	})
	ensure('verify JWT with RS256', cb => {
		cb(null, rsJwt.verify(rsJwt.create(payload)))
	})
})
