package payment

import (
	. "gopkg.in/check.v1"
	"log"
)

type APPaySuite struct {
}

var _ = Suite(&APPaySuite{})

func (this *APPaySuite) SetUpSuite(c *C) {
	AP_PAY_CONFIG.PARTNER_ID = ""
	AP_PAY_CONFIG.SELLER_EMAIL = ""
	AP_PAY_CONFIG.SIGN_TYPE = "RSA"
	AP_PAY_CONFIG.ALIPAY_KEY = ""
	AP_PAY_CONFIG.PARTNET_PRIVATE_KEY = ``
	AP_PAY_CONFIG.ALIPAY_PUBLIC_KEY = ``
	InitAPKey()
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
