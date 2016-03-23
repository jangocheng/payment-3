package payment

import (
	. "gopkg.in/check.v1"
	"log"
)

type APPaySuite struct {
}

var _ = Suite(&APPaySuite{})

func (this *APPaySuite) SetUpSuite(c *C) {
	conf := APKeyConfig{}
	conf.PARTNER_ID = "2088911192198364"
	conf.SELLER_EMAIL = "finance@health-com.cn"
	conf.SIGN_TYPE = "RSA"
	conf.ALIPAY_KEY = "dv5rgr9x5iy6eo4lafijdxyl6e5xdns8"
	conf.PARTNET_PRIVATE_KEY = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwweGJ9ag9qalHC+v7VSVnr2sJ7/QhlaN0d+XRwDTJKOv8E7W
dwE2xMsQJx+6ZaMNCWcosrQCkcvkzCNpDVq71WjBM5hedQSkHa7afgyd87Iem7uv
2p1udgiNSkZxJcDLJxZ7Ak0vWYYl9iK9db8RzCLRkmNTpwUNoZSCJO7xSejy+7fC
ZB7X8ocCViilPs2Q2onbmZUHnKhF/XUPBHlipyRlnhl1Y2GIfoNmmmTQFu0K+aE0
Zc0mtyZSZM0/WJ79zCV4G1IoJlUiPCz1yq4z3uGPAgYbKiImMOTqOm4GbZjKE3Ti
2VNY/4jFRKmTBxmwrbGsHjUBeWKLK6zZwI2UDwIDAQABAoIBAGaCeupPrtVWLCzP
h+n37pi8W1OdR66EqhBpNKt2bISyoNRvq9xrP+1aSog17hRkCoMpvMOJSFx3zi/a
YOpLCbWXVQ2YhfV91gFgGantWcxwkBQNJ9aBr0DNJ+6lbe2JE37dGxTPmxa0Ixnn
kqvkHSeuGXeXS63bQxnt5CYjjaHpq3PSJki55IZmN741vE5nrkIcT1gbeVEhO805
fg4qndO0KydnrSDV/zbNW6CtQHCnwcUKKo5BaO5oG38ca8GfVRRuSLYij2kqFOj2
rqgxo5qpb8ok3WP/I7REMuktcBlCBePIaj47qXP9iwC8cAqnf/EbqsffvanM4Evr
2CxDTPECgYEA5Cy2flMglgPn3V6kkNumTE62HcQ88LkGL4euIC2nZ5oS0ZWbnR/w
XPRXppCHb5T3HLK1FYvLyXxJTlda1kfNarSoeUwLRHqlY8+QnSvgUoR+JMH0t7BQ
ZyoSAgXh75PDUVPdKdUqwxpco1My7sZdUXNmEM4CkQ2P5GWW9zWQRtkCgYEA2tAQ
LjfUeYEWb+XHw4eAgLUZPU5sPbU7oJb8uLlXUgWdXL6TvBBRhKAF9tMnRunejCZ5
2oV2ZbX78JwMD9rsWm0/WSlHwToLa7s4CxJGn+31nZtB7bL+s+uxAJX9Oj4yuybz
WRkK1reWGfHTBt0OyQGQiV5946c4cV0U9IyVcScCgYA4y6xtS1HMJZK8doduC06c
pecNB8DHhra0dAhyuAp4blCK3LuMY9vXt3Zt3oHn02OjQBR1FYQXVhmFJ5dTyTGn
guqArt4LIKA0dQEhLj+7KoGfsquwYXHSDBXJbR9tHBG9F6vwcsAfKluux9Hgv32Q
/bGFM1JOOtr7VhI63JlaGQKBgDv22PhRhIDnx2ZS6jPDZovfFVOfsjoW+IhB2HAn
Gq73qvBHqeTX8/8Me5Xwt8rPPJXb1Xj1KkUlYi3GFegibrM5TSr6DRf++DJF1E30
bDZX1/+hFKg3bWWRKaincgYMFYsEWZwJKNc+6Hujsdknq22aaCm9I3LH2Mf4Yk3C
WRHxAoGAY6vPk+hLEUI6OUZDGdOtF9q69bug1pgJUMApbXbQLuvpNv6j7t7vk+ve
wc0ypMFUlXN1dqXHjUkS1GliAMWmIeX84JlyzuHJpsGzdnjwD4muBqMvsUOmNGaG
Uzo+hfi0oFGINUgDryA2TWPCxN3b+cay0eD6N10jsrB3vyNY9jw=
-----END RSA PRIVATE KEY-----
`
	conf.ALIPAY_PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnxj/9qwVfgoUh/y2W89L6BkRA
FljhNhgPdyPuBV64bfQNN1PjbCzkIM6qRdKBoLPXmKKMiFYnkd6rAoprih3/PrQE
B/VsW8OoM8fxn67UDYuyBTqA23MML9q1+ilIZwBC2AQ2UBVOrFXfFl75p6/B5Ksi
NG9zpgmLCUYuLkxpLQIDAQAB
-----END PUBLIC KEY-----
`
	InitAPKey(conf)
}

func (this *APPaySuite) TearDownSuite(c *C) {

}

func (this *APPaySuite) TestSign(c *C) {
	a := NewAPPayReqForApp()
	a.NotifyURL = "http://www.cegu.com/callback"
	a.OutTradeNO = "123456789012345"
	a.Subject = "test"
	a.TotalFee = "0.01"
	a.Body = "测试"
	log.Println(a)
}
