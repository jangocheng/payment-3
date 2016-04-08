package payment

import (
	"encoding/json"
	. "gopkg.in/check.v1"
	"log"
)

type APPaySuite struct {
}

var _ = Suite(&APPaySuite{})

func (this *APPaySuite) SetUpSuite(c *C) {
	conf := APKeyConfig{
		PARTNER_ID:   "2088121797205248",
		SELLER_EMAIL: "57730141@qq.com",
		SIGN_TYPE:    "RSA",
		ALIPAY_KEY:   "nnaw7ids3897wpfrwusckkjlp8bksrl2",
		PARTNET_PRIVATE_KEY: `
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCHdorzBpbvkwB+ngQIe2MnvMRlbDRTh3RzWWw8T+IVvDOlvGr
rP9B7hQZ/g1LJ3/V2dGay2BSqJjYDbvBVUUp0TmPwDSWfFaCEvJ1PunpVDdUukzY
1s6qINc7kYwRoXylWYKvVoozL3wOjQUJzgpCm8IPZqG+zgCRUAymchsvWwIDAQAB
AoGACPKxVOWCrYn3HPw7vpqhxaKqF7xruyo7q6kpL9/fCtzfGtbQaxZ9ab+cw5n3
aOh4NxZkWBtZ5FWLPiJb7kyM9IzxCSj/q3sKbJZg7yTZaGX04ZsiZWpjoOdIITA/
wgKqpk1huRwcS7/Bfbe+TQLukKE9AAZfxKnY2u16BxjfTCkCQQDq19uDCJya+yka
QD1srr3wB31PEbUdYQjdXul+BkDAruazHPOkwxzNIK6B6cNQXV8cO/0w51mmIy97
2iwMhBxNAkEA05q5vn/puC5hzRh0g3X1S9e/sLe+5thgsvw4n0OG8uHUrgWYoElu
AErPiqOO7I0l83rHRJM99CEbzi81mKeuRwJBANAvv6dv0PULRqrA3DMmzbalzQ51
UivTQ7qLU06nWGv4IQgT2GHtnfCy0kDU7JKn05MCEzhxP2YqtwOCq54E19kCQQCD
TgCyeDc0ZfukQ+eQ57Jl9KPraamZH22pwx7znPhxYLcToT9bPxV2MvXkJqf6m3+Q
PYDHScLo6V6Sq/LLHknjAkEAhaujA61MtbQzMjFQUdCPU8ljFis+5Mxjo4kNcSE9
+YuKJYCgKOo+aFxs+K2WYarASVme3kkgqttzwMuVdhZu7g==
-----END RSA PRIVATE KEY-----
`,
		ALIPAY_PUBLIC_KEY: `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnxj/9qwVfgoUh/y2W89L6BkRA
FljhNhgPdyPuBV64bfQNN1PjbCzkIM6qRdKBoLPXmKKMiFYnkd6rAoprih3/PrQE
B/VsW8OoM8fxn67UDYuyBTqA23MML9q1+ilIZwBC2AQ2UBVOrFXfFl75p6/B5Ksi
NG9zpgmLCUYuLkxpLQIDAQAB
-----END PUBLIC KEY-----
`,
	}
	InitAPKey(conf)
}

func (this *APPaySuite) TearDownSuite(c *C) {

}

func (this *APPaySuite) TestValid(c *C) {
	log.Printf("%0.2f", 0.009999999776482582)
	j := `{"NotifyTime":"2016-03-24 17:40:07","NotifyType":"trade_status_sync","NotifyId":"b0b55aa366562ded418e27274241493k8u","SignType":"RSA","Sign":"XW4MuVccJicaaSREj/pByvlkNOdHjgGCl+S83yVrSczL2wWIYf6IeJB6L0k2xq/bUNKl+AJFkjEMHASaBkG71zjVvksp0WWxlcDjIkc/otA+ZKLtgv4hDHe20+Y6q8amU9vz1HrpWzyfXMt/s9fe8744r+52Ne9pKuvkQGM3Pbg=","OutTradeNO":"201603241725160001","Subject":"test","PaymentType":"1","TradeNO":"2016032421001004550262574276","TradeStatus":"TRADE_SUCCESS","SellerId":"2088121797205248","SellerEmail":"57730141@qq.com","BuyerId":"2088002003565555","BuyerEmail":"cxuhua@gmail.com","TotalFee":"0.01","Quantity":"1","Price":"0.01","Body":"测试","GMTCreate":"2016-03-24 17:26:17","GMTPayment":"2016-03-24 17:26:18","FeeAdjust":"N","UseCoupon":"N","Discount":"0.00","RefundStatus":"","GMTRefund":""}`
	v := APPayResultNotifyArgs{}
	json.Unmarshal([]byte(j), &v)
	log.Println(v.IsFromAlipay())
	log.Println(v.IsValid())
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
