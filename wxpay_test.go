package payment

import (
	. "gopkg.in/check.v1"
	"log"
)

type WXPaySuite struct {
}

var _ = Suite(&WXPaySuite{})

func (this *WXPaySuite) SetUpSuite(c *C) {
	WX_PAY_CONFIG.APP_ID = ""
	WX_PAY_CONFIG.APP_SECRET = ""
	WX_PAY_CONFIG.MCH_ID = ""
	WX_PAY_CONFIG.MCH_KEY = ""
	InitWXKey()
}

func (this *WXPaySuite) TearDownSuite(c *C) {

}

func (this *WXPaySuite) TestWXOAuth2Authorize(c *C) {
	a := WXOAuth2Authorize{}
	a.State = "state1"
	a.RedirectURI = "http://wx.rockygame.cn/callback"
	log.Println(a.ToURL())
}

func (this *WXPaySuite) TestPayReq(c *C) {
	req := NewWXPayReqForApp("testpayid")
	log.Println(req)
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