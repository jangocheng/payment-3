package payment

import (
	. "gopkg.in/check.v1"
	"log"
)

type WXPaySuite struct {
}

var _ = Suite(&WXPaySuite{})

func (this *WXPaySuite) SetUpSuite(c *C) {
	conf := WXKeyConfig{}
	conf.APP_ID = "wx21b3ee9bd6d16364"
	conf.APP_SECRET = "d7eeecfd00f3190f06d4b693608a7432"
	conf.MCH_ID = "1230573602"
	conf.MCH_KEY = "36507e7df83200a1850752db0a208a91"
	InitWXKey(conf)
}

func (this *WXPaySuite) TearDownSuite(c *C) {

}

func (this *WXPaySuite) TestWXOAuth2Authorize(c *C) {
	a := WXOAuth2Authorize{}
	a.State = "state1"
	a.RedirectURI = "http://www.pzhnf.com/userinfo/pay"
	log.Println(a.ToURL())
}

func (this *WXPaySuite) TestPayReq(c *C) {
	a := WXPayQueryOrder{}
	a.OutTradeNo = "12121212"
	ret, _ := a.Post()
	log.Println(ret.ErrCode)
}

func (this *WXPaySuite) TestWXUnifiedorder(c *C) {
	a := WXUnifiedorderRequest{}
	a.Body = "aabcd"
	a.DeviceInfo = "WEB"
	a.OutTradeNo = "23829372372873"
	a.TotalFee = "100"
	a.SpBillCreateIp = "123.12.12.123"
	a.TradeType = TRADE_TYPE_JSAPI
	a.OpenId = "oUpF8uMuAJO_M2pxb1Q9zNjWeS6o"
	if ret, err := a.Post(); err != nil {
		log.Println(err)
	} else {
		log.Println(ret)
	}
}
