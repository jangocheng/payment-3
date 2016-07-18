package payment

import (
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/cxuhua/xweb"
	"html/template"
	"reflect"
	"strings"
)

/**
 * TODO: 修改这里配置为您自己申请的商户信息
 * 微信公众号信息配置
 *
 * AppId：绑定支付的APPID（必须配置，开户邮件中可查看）
 *
 * MchId：商户号（必须配置，开户邮件中可查看）
 *
 * MchKey：商户支付密钥，参考开户邮件设置（必须配置，登录商户平台自行设置）
 * 设置地址：https://pay.weixin.qq.com/index.php/account/api_cert
 *
 * AppSecret：公众帐号secert（仅JSAPI支付的时候需要配置， 登录公众平台，进入开发者中心可设置），
 * 获取地址：https://mp.weixin.qq.com/advanced/advanced?action=dev&t=advanced/dev&token=2005451881&lang=zh_CN
 * @var string
 */

type WXKeyConfig struct {
	APP_ID     string
	APP_SECRET string
	MCH_ID     string
	MCH_KEY    string
	CRT_PATH   string
	KEY_PATH   string
	CA_PATH    string
	TLSConfig  *tls.Config
}

var (
	WX_PAY_CONFIG WXKeyConfig = WXKeyConfig{}
)

func InitWXKey(conf WXKeyConfig) {
	WX_PAY_CONFIG = conf
	if conf.CA_PATH != "" && conf.CRT_PATH != "" && conf.KEY_PATH != "" {
		WX_PAY_CONFIG.TLSConfig = xweb.MustLoadTLSFileConfig(conf.CA_PATH, conf.CRT_PATH, conf.KEY_PATH)
	}
}

func WXSign(v interface{}) string {
	http := WXParseSignFields(v)
	str := http.RawEncode() + "&key=" + WX_PAY_CONFIG.MCH_KEY
	return strings.ToUpper(xweb.MD5String(str))
}

func WXParseSignFields(src interface{}) xweb.HTTPValues {
	values := xweb.NewHTTPValues()
	t := reflect.TypeOf(src)
	v := reflect.ValueOf(src)
	for i := 0; i < t.NumField(); i++ {
		tf := t.Field(i)
		if tf.Tag.Get("sign") != "true" {
			continue
		}
		tv := v.Field(i)
		if !tv.IsValid() {
			continue
		}
		sv := fmt.Sprintf("%v", tv.Interface())
		if sv == "" {
			continue
		}
		name := ""
		if xn := tf.Tag.Get("xml"); xn != "" {
			name = strings.Split(xn, ",")[0]
		} else if xn = tf.Tag.Get("json"); xn != "" {
			name = strings.Split(xn, ",")[0]
		} else {
			continue
		}
		values.Add(name, sv)
	}
	return values
}

//支付类型
const (
	TRADE_TYPE_JSAPI  = "JSAPI"
	TRADE_TYPE_NATIVE = "NATIVE"
	TRADE_TYPE_APP    = "APP"
)

//转账校验
const (
	NO_CHECK     = "NO_CHECK"     //不校验真实姓名
	FORCE_CHECK  = "FORCE_CHECK"  //强制校验
	OPTION_CHECK = "OPTION_CHECK" //有则校验
)

//返回字符串
const (
	FAIL       = "FAIL"
	NOTPAY     = "NOTPAY"
	SUCCESS    = "SUCCESS"
	USERPAYING = "USERPAYING"
)

//主机地址
const (
	//公众号
	WX_API_HOST = "https://api.weixin.qq.com"
	//支付
	WX_PAY_HOST = "https://api.mch.weixin.qq.com"
)

//应用授权作用域
const (
	WX_BASE_SCOPE = "snsapi_base"     //只能获得openid,不需要用户确认
	WX_INFO_SCOPE = "snsapi_userinfo" //需要用户确认,能够获得用户信息
)

type WXError struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

func (this WXError) Error() error {
	if this.ErrCode == 0 {
		return nil
	}
	return errors.New(fmt.Sprintf("ERROR:%d,%s", this.ErrCode, this.ErrMsg))
}

type WXGetAccessTokenResponse struct {
	WXError
	AccessToken string `json:"access_token"`
	Expires     int    `json:"expires_in"`
}

//微信转账
type WXTransfersRequest struct {
	AppId          string `xml:"mch_appid" sign:"true"`
	MchId          string `xml:"mchid" sign:"true"`
	NonceStr       string `xml:"nonce_str" sign:"true"`
	Sign           string `xml:"sign" sign:"false"`
	PartnerTradeNo string `xml:"partner_trade_no" sign:"true"`
	OpenId         string `xml:"openid" sign:"true"`
	CheckName      string `xml:"check_name" sign:"true"`
	Amount         int    `xml:"amount" sign:"true"`
	Desc           string `xml:"desc" sign:"true"`
	SpbillCreateIp string `xml:"spbill_create_ip" sign:"true"`
}

func (this WXTransfersRequest) ToXml() string {
	data, err := xml.Marshal(this)
	if err != nil {
		panic(err)
	}
	return string(data)
}

type WXTransfersResponse struct {
	ReturnCode string `xml:"return_code"`
	ReturnMsg  string `xml:"return_msg"`
	ResultCode string `xml:"result_code"`
	ErrCodeDes string `xml:"err_code_des"`
}

func (this WXTransfersRequest) Post() (WXTransfersResponse, error) {
	ret := WXTransfersResponse{}
	this.PartnerTradeNo = xweb.GenId()
	this.NonceStr = RandStr()
	this.MchId = WX_PAY_CONFIG.MCH_ID
	this.AppId = WX_PAY_CONFIG.APP_ID
	if this.Amount <= 0 {
		return ret, errors.New("Amount error")
	}
	if this.SpbillCreateIp == "" {
		return ret, errors.New("SpbillCreateIp miss")
	}
	if this.Desc == "" {
		return ret, errors.New("Desc miss")
	}
	if this.CheckName == "" {
		return ret, errors.New("CheckName miss")
	}
	vs := WXParseSignFields(this)
	this.Sign = strings.ToUpper(vs.MD5Sign(WX_PAY_CONFIG.MCH_KEY))
	body := strings.NewReader(this.ToXml())
	http := xweb.NewHTTPClient(WX_PAY_HOST, WX_PAY_CONFIG.TLSConfig)
	res, err := http.Post("/mmpaymkttransfers/promotion/transfers", "application/xml", body)
	if err != nil {
		return ret, err
	}
	if err := res.ToXml(&ret); err != nil {
		return ret, err
	}
	if ret.ReturnCode != SUCCESS || ret.ResultCode != SUCCESS {
		return ret, errors.New(ret.ReturnMsg)
	}
	return ret, nil
}

//微信红包发送
type WXRedPackageRequest struct {
	MchBillno   string `xml:"mch_billno" sign:"true"`
	NonceStr    string `xml:"nonce_str" sign:"true"`
	MchId       string `xml:"mch_id" sign:"true"`
	AppId       string `xml:"wxappid" sign:"true"`
	SendName    string `xml:"send_name" sign:"true"`
	ReOpenId    string `xml:"re_openid" sign:"true"`
	TotalAmount int    `xml:"total_amount" sign:"true"`
	TotalNum    int    `xml:"total_num" sign:"true"`
	Wishing     string `xml:"wishing" sign:"true"`
	ClientIp    string `xml:"client_ip" sign:"true"`
	ActName     string `xml:"act_name" sign:"true"`
	Remark      string `xml:"remark" sign:"true"`
	Sign        string `xml:"sign" sign:"false"`
}

func (this WXRedPackageRequest) ToXml() string {
	data, err := xml.Marshal(this)
	if err != nil {
		panic(err)
	}
	return string(data)
}

type WXRedPackageResponse struct {
	ReturnCode string `xml:"return_code"`
	ReturnMsg  string `xml:"return_msg"`
	ResultCode string `xml:"result_code"`
	ErrCodeDes string `xml:"err_code_des"`
}

func (this WXRedPackageRequest) Post() (WXRedPackageResponse, error) {
	ret := WXRedPackageResponse{}
	this.MchBillno = xweb.GenId()
	this.NonceStr = RandStr()
	this.MchId = WX_PAY_CONFIG.MCH_ID
	this.AppId = WX_PAY_CONFIG.APP_ID
	if this.SendName == "" {
		return ret, errors.New("SendName miss")
	}
	if this.ReOpenId == "" {
		return ret, errors.New("ReOpenId miss")
	}
	if this.TotalAmount <= 0 {
		return ret, errors.New("TotalAmount error")
	}
	if this.TotalNum <= 0 {
		return ret, errors.New("TotalNum error")
	}
	if this.ClientIp == "" {
		return ret, errors.New("ClientIp miss")
	}
	if this.ActName == "" {
		return ret, errors.New("ActName miss")
	}
	if this.Remark == "" {
		return ret, errors.New("Remark miss")
	}
	if this.Wishing == "" {
		return ret, errors.New("Wishing miss")
	}
	vs := WXParseSignFields(this)
	this.Sign = strings.ToUpper(vs.MD5Sign(WX_PAY_CONFIG.MCH_KEY))
	body := strings.NewReader(this.ToXml())
	http := xweb.NewHTTPClient(WX_PAY_HOST, WX_PAY_CONFIG.TLSConfig)
	res, err := http.Post("/mmpaymkttransfers/sendredpack", "application/xml", body)
	if err != nil {
		return ret, err
	}
	if err := res.ToXml(&ret); err != nil {
		return ret, err
	}
	if ret.ReturnCode != SUCCESS || ret.ResultCode != SUCCESS {
		return ret, errors.New(ret.ReturnMsg)
	}
	return ret, nil
}

//https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=$this->appId&secret=$this->appSecret"
func WXGetAccessToken() (WXGetAccessTokenResponse, error) {
	ret := WXGetAccessTokenResponse{}
	q := xweb.NewHTTPValues()
	q.Set("grant_type", "client_credential")
	q.Set("appid", WX_PAY_CONFIG.APP_ID)
	q.Set("secret", WX_PAY_CONFIG.APP_SECRET)
	c := xweb.NewHTTPClient("https://api.weixin.qq.com")
	res, err := c.Get("/cgi-bin/token", q)
	if err != nil {
		return ret, err
	}
	if err := res.ToJson(&ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
	}
	return ret, err
}

//公众号用户所有Tag
type WXTag struct {
	Id    int    `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"count"` //此标签下粉丝数
}

//获得公众号用户标签列表
type WXGetTagsResponse struct {
	WXError
	Tags []WXTag `json:"tags"`
}

func WXGetTags(token string) (WXGetTagsResponse, error) {
	ret := WXGetTagsResponse{}
	q := xweb.NewHTTPValues()
	q.Set("access_token", token)
	http := xweb.NewHTTPClient("https://api.weixin.qq.com")
	res, err := http.Get("/cgi-bin/tags/get", q)
	if err != nil {
		return ret, err
	}
	if err := res.ToJson(&ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
	}
	return ret, nil
}

//获取 jsapi_ticket 票据接口
//https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=ACCESS_TOKEN&type=jsapi
type WXGetJSApiTicketResponse struct {
	WXError
	Ticket  string `json:"ticket"`
	ExpTime int    `json:"expires_in"`
}

func WXGetJSApiTicket(token string) (WXGetJSApiTicketResponse, error) {
	ret := WXGetJSApiTicketResponse{}
	if token == "" {
		return ret, errors.New("token miss")
	}
	q := xweb.NewHTTPValues()
	q.Set("access_token", token)
	q.Set("type", "jsapi")
	c := xweb.NewHTTPClient("https://api.weixin.qq.com")
	res, err := c.Get("/cgi-bin/ticket/getticket", q)
	if err != nil {
		return ret, err
	}
	if err := res.ToJson(&ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
	}
	return ret, err
}

//https://open.weixin.qq.com/connect/oauth2/authorize
//授权成功后将跳转至:redirect_uri?code=v&state=v,通过query获得到code和state
type WXOAuth2Authorize struct {
	AppId        string `json:"appid" sign:"true"`         //公众号的唯一标识
	ResponseType string `json:"response_type" sign:"true"` //返回类型，请填写code
	Scope        string `json:"scope" sign:"true"`         //应用授权作用域
	State        string `json:"state" sign:"true"`         //自定义状态
	RedirectURI  string `json:"redirect_uri" sign:"true"`  //跳转地址
}

func (this WXOAuth2Authorize) ToURL() string {
	this.AppId = WX_PAY_CONFIG.APP_ID
	this.ResponseType = "code"
	if this.Scope == "" {
		this.Scope = WX_BASE_SCOPE
	}
	if this.State == "" {
		panic(errors.New("must set state"))
	}
	v := WXParseSignFields(this)
	return "https://open.weixin.qq.com/connect/oauth2/authorize?" + v.Encode() + "#wechat_redirect"
}

//网页授权接口调用凭证获取
//https://api.weixin.qq.com/sns/oauth2/access_token
type WXOAuth2AccessTokenRequest struct {
	AppId     string `json:"appid,omitempty" sign:"true"`      //公众号的唯一标识
	AppSecret string `json:"secret,omitempty" sign:"true"`     //公众号安全代码
	Code      string `json:"code,omitempty" sign:"true"`       //跳转过来的code
	GrantType string `json:"grant_type,omitempty" sign:"true"` //authorization_code
}

//
type WXOAuth2AccessTokenResponse struct {
	WXError
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionId      string `json:"unionid"`
}

func (this WXOAuth2AccessTokenRequest) Get() (WXOAuth2AccessTokenResponse, error) {
	ret := WXOAuth2AccessTokenResponse{}
	this.AppId = WX_PAY_CONFIG.APP_ID
	this.AppSecret = WX_PAY_CONFIG.APP_SECRET
	if this.Code == "" {
		panic(errors.New("code miss"))
	}
	this.GrantType = "authorization_code"
	v := WXParseSignFields(this)
	http := xweb.NewHTTPClient(WX_API_HOST)
	res, err := http.Get("/sns/oauth2/access_token", v)
	if err != nil {
		return ret, err
	}
	if err := res.ToJson(&ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
	}
	return ret, nil
}

//https://api.mch.weixin.qq.com/secapi/pay/refund
//微信退款发起请求
type WXRefundRequest struct {
	XMLName       struct{} `xml:"xml"`
	AppId         string   `xml:"appid,omitempty" sign:"true"`
	MchId         string   `xml:"mch_id,omitempty" sign:"true"`
	NonceStr      string   `xml:"nonce_str,omitempty" sign:"true"`
	OPUserId      string   `xml:"op_user_id,omitempty" sign:"true"`
	OutRefundNO   string   `xml:"out_refund_no,omitempty" sign:"true"`
	OutTradeNO    string   `xml:"out_trade_no,omitempty" sign:"true"`
	RefundFee     string   `xml:"refund_fee,omitempty" sign:"true"`
	Sign          string   `xml:"sign,omitempty" sign:"false"`
	TotalFee      string   `xml:"total_fee,omitempty" sign:"true"`
	TransactionId string   `xml:"transaction_id,omitempty" sign:"true"`
}

func (this WXRefundRequest) ToXML() string {
	data, err := xml.Marshal(this)
	if err != nil {
		panic(err)
	}
	return string(data)
}

type WXRefundResponse struct {
	XMLName            struct{} `xml:"xml"`
	AppId              string   `xml:"appid" sign:"true"`
	CashFee            string   `xml:"cash_fee,omitempty" sign:"true"`
	CashRefundFee      string   `xml:"cash_refund_fee,omitempty" sign:"true"`
	device_info        string   `xml:"device_info,omitempty" sign:"true"`
	ErrCode            string   `xml:"err_code" sign:"true"`
	ErrCodeDes         string   `xml:"err_code_des" sign:"true"`
	FeeType            string   `xml:"fee_type,omitempty" sign:"true"`
	MchId              string   `xml:"mch_id" sign:"true"`
	NonceStr           string   `xml:"nonce_str" sign:"true"`
	OutRefundNO        string   `xml:"out_refund_no,omitempty" sign:"true"`
	OutTradeNO         string   `xml:"out_trade_no,omitempty" sign:"true"`
	RefundChannel      string   `xml:"refund_channel,omitempty" sign:"true"`
	RefundFee          string   `xml:"refund_fee,omitempty" sign:"true"`
	RefundId           string   `xml:"refund_id,omitempty" sign:"true"`
	ResultCode         string   `xml:"result_code" sign:"true"`
	ReturnCode         string   `xml:"return_code" sign:"true"`
	ReturnMsg          string   `xml:"return_msg" sign:"true"`
	SettlementTotalFee string   `xml:"settlement_total_fee,omitempty" sign:"true"`
	Sign               string   `xml:"sign" sign:"false"`
	TotalFee           string   `xml:"total_fee,omitempty" sign:"true"`
	TransactionId      string   `xml:"transaction_id,omitempty" sign:"true"`
}

func (this WXRefundResponse) SignValid() bool {
	sign := WXSign(this)
	return sign == this.Sign
}

func (this WXRefundRequest) Post() (WXRefundResponse, error) {
	ret := WXRefundResponse{}
	this.AppId = WX_PAY_CONFIG.APP_ID
	this.MchId = WX_PAY_CONFIG.MCH_ID
	this.OPUserId = WX_PAY_CONFIG.MCH_ID
	this.NonceStr = RandStr()
	if this.TransactionId == "" {
		panic(errors.New("TransactionId miss"))
	}
	if this.OutTradeNO == "" {
		panic(errors.New("OutTradeNO miss"))
	}
	if this.OutRefundNO == "" {
		panic(errors.New("OutRefundNO miss"))
	}
	if this.TotalFee == "" {
		panic(errors.New("TotalFee miss"))
	}
	if this.RefundFee == "" {
		panic(errors.New("RefundFee miss"))
	}
	if WX_PAY_CONFIG.TLSConfig == nil {
		panic(errors.New("wx pay key config miss"))
	}
	this.Sign = WXSign(this)
	http := xweb.NewHTTPClient(WX_PAY_HOST, WX_PAY_CONFIG.TLSConfig)
	res, err := http.Post("/secapi/pay/refund", "application/xml", strings.NewReader(this.ToXML()))
	if err != nil {
		return ret, NET_ERROR
	}
	if err := res.ToXml(&ret); err != nil {
		return ret, DATA_UNMARSHAL_ERROR
	}
	if !ret.SignValid() {
		return ret, errors.New("sign error")
	}
	return ret, nil
}

//刷新网页授权凭证
//https://api.weixin.qq.com/sns/oauth2/refresh_token
type WXOAuth2RefreshTokenRequest struct {
	AppId        string `json:"appid,omitempty" sign:"true"`
	RefreshToken string `json:"refresh_token,omitempty" sign:"true"`
	GrantType    string `json:"grant_type,omitempty" sign:"true"`
}

type WXOAuth2RefreshTokenResponse struct {
	WXError
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
	Scope        string `json:"scope"`
}

func (this WXOAuth2RefreshTokenRequest) Get() (WXOAuth2RefreshTokenResponse, error) {
	ret := WXOAuth2RefreshTokenResponse{}
	this.AppId = WX_PAY_CONFIG.APP_ID
	if this.RefreshToken == "" {
		panic(errors.New("RefreshToken miss"))
	}
	this.GrantType = "refresh_token"
	v := WXParseSignFields(this)
	http := xweb.NewHTTPClient(WX_API_HOST)
	res, err := http.Get("/sns/oauth2/refresh_token", v)
	if err != nil {
		return ret, err
	}
	if err := res.ToJson(&ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
	}
	return ret, nil
}

//拉取用户信息
//https://api.weixin.qq.com/cgi-bin/user/info
type WXUserInfoRequest struct {
	AccessToken string `json:"access_token" sign:"true"`
	OpenId      string `json:"openid" sign:"true"`
	Lang        string `json:"lang" sign:"true"`
}

/*
{"openid":"oW2MRwIqhll39pDiOdpsAyrmT0gU",
"nickname":"徐华",
"sex":1,
"language":"zh_CN",
"city":"成都",
"province":"四川",
"country":"中国",
"headimgurl":"http:\/\/wx.qlogo.cn\/mmopen\/mWfv8OZyiccr8DSUkdkhSq4lopNL9wC614Siao90qq0XIwIrt0twI5jicLgLz4KYWVW2JntDoQDj73Ho3BK1znuykLT2BS9ZSCI\/0",
"privilege":[]}
*/
type WXUserInfoResponse struct {
	WXError
	Subscribe  int      `json:"subscribe"`
	OpenId     string   `json:"openid"`
	NickName   string   `json:"nickname"`
	Language   string   `json:"language"`
	Sex        int      `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgURL string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	UnionId    string   `json:"unionid"`
	GroupId    int      `json:"groupid"`
	TagidList  []int    `json:"tagid_list"`
}

func (this WXUserInfoRequest) Get() (WXUserInfoResponse, error) {
	ret := WXUserInfoResponse{}
	if this.AccessToken == "" {
		panic(errors.New("AccessToken miss"))
	}
	if this.OpenId == "" {
		panic(errors.New("OpenId miss"))
	}
	if this.Lang == "" {
		this.Lang = "zh_CN"
	}
	v := WXParseSignFields(this)
	http := xweb.NewHTTPClient(WX_API_HOST)
	res, err := http.Get("/cgi-bin/user/info", v)
	if err != nil {
		return ret, err
	}
	if err := res.ToJson(&ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
	}
	return ret, nil
}

//检验授权凭证（access_token,openid）是否有效
//GET https://api.weixin.qq.com/sns/auth?access_token=ACCESS_TOKEN&openid=OPENID
func AuthGet(token, openid string) WXError {
	ret := WXError{}
	if token == "" {
		panic(errors.New("token error"))
	}
	if openid == "" {
		panic(errors.New("openid error"))
	}
	http := xweb.NewHTTPClient(WX_API_HOST)
	v := xweb.NewHTTPValues()
	v.Set("access_token", token)
	v.Set("openid", openid)
	res, err := http.Get("/sns/auth", v)
	if err != nil {
		ret.ErrCode = 1000000
		ret.ErrMsg = err.Error()
		return ret
	}
	if err := res.ToJson(&ret); err != nil {
		ret.ErrCode = 1000001
		ret.ErrMsg = err.Error()
		return ret
	}
	return ret
}

type WXPayQueryOrderResponse struct {
	XMLName        struct{} `xml:"xml"`
	AppId          string   `xml:"appid" sign:"true"`
	Attach         string   `xml:"attach" sign:"true"`
	BankType       string   `xml:"bank_type" sign:"true"`
	CashFee        string   `xml:"cash_fee" sign:"true"`
	ErrCode        string   `xml:"err_code" sign:"true"`
	ErrCodeDes     string   `xml:"err_code_des" sign:"true"`
	FeeType        string   `xml:"fee_type" sign:"true"`
	IsSubScribe    string   `xml:"is_subscribe" sign:"true"`
	MchId          string   `xml:"mch_id" sign:"true"`
	NonceStr       string   `xml:"nonce_str" sign:"true"`
	OpenId         string   `xml:"openid" sign:"true"`
	OutTradeNo     string   `xml:"out_trade_no" sign:"true"`
	ResultCode     string   `xml:"result_code" sign:"true"`
	ReturnCode     string   `xml:"return_code" sign:"true"`
	ReturnMsg      string   `xml:"return_msg" sign:"true"`
	Sign           string   `xml:"sign" sign:"false"`
	TimeEnd        string   `xml:"time_end" sign:"true"`
	TotalFee       string   `xml:"total_fee" sign:"true"`
	TradeState     string   `xml:"trade_state" sign:"true"`
	TradeStateDesc string   `xml:"trade_state_desc" sign:"true"`
	TradeType      string   `xml:"trade_type" sign:"true"`
	TransactionId  string   `xml:"transaction_id" sign:"true"`
}

func (this WXPayQueryOrderResponse) SignValid() bool {
	sign := WXSign(this)
	return sign == this.Sign
}

//正在支付
func (this WXPayQueryOrderResponse) IsPaying() bool {
	if this.ReturnCode != SUCCESS {
		return false
	}
	if this.ResultCode != SUCCESS {
		return false
	}
	return this.TradeState == USERPAYING
}

//支付成功
func (this WXPayQueryOrderResponse) IsPaySuccess() bool {
	if this.ReturnCode != SUCCESS {
		return false
	}
	if this.ResultCode != SUCCESS {
		return false
	}
	return this.TradeState == SUCCESS
}

//2201604122135130001
//https://api.mch.weixin.qq.com/pay/orderquery
type WXPayQueryOrder struct {
	XMLName    struct{} `xml:"xml"`
	AppId      string   `xml:"appid" sign:"true"`
	MchId      string   `xml:"mch_id" sign:"true"`
	OutTradeNo string   `xml:"out_trade_no" sign:"true"`
	NonceStr   string   `xml:"nonce_str" sign:"true"`
	Sign       string   `xml:"sign" sign:"false"` //sign=false表示不参与签名
}

func (this WXPayQueryOrder) ToXML() string {
	data, err := xml.Marshal(this)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (this WXPayQueryOrder) Post() (WXPayQueryOrderResponse, error) {
	ret := WXPayQueryOrderResponse{}
	this.NonceStr = RandStr()
	this.AppId = WX_PAY_CONFIG.APP_ID
	this.MchId = WX_PAY_CONFIG.MCH_ID
	if this.AppId == "" {
		panic(errors.New("AppId miss"))
	}
	if this.MchId == "" {
		panic(errors.New("MchId miss"))
	}
	this.Sign = WXSign(this)
	http := xweb.NewHTTPClient(WX_PAY_HOST)
	res, err := http.Post("/pay/orderquery", "application/xml", strings.NewReader(this.ToXML()))
	if err != nil {
		return ret, NET_ERROR
	}
	if err := res.ToXml(&ret); err != nil {
		return ret, DATA_UNMARSHAL_ERROR
	}
	if !ret.SignValid() {
		return ret, errors.New("sign error")
	}
	return ret, nil
}

//支付结果通用通知
//微信服务器将会根据统一下单的NotifyURL POST以下数据到商机服务器处理
type WXPayResultNotifyArgs struct {
	xweb.XMLArgs  `xml:"-"`
	XMLName       struct{} `xml:"xml"` //root node name
	AppId         string   `xml:"appid" sign:"true"`
	Attach        string   `xml:"attach" sign:"true"`
	BankType      string   `xml:"bank_type" sign:"true"`
	CashFee       string   `xml:"cash_fee" sign:"true"`
	CashFeeType   string   `xml:"cash_fee_type" sign:"true"`
	CouponCount   string   `xml:"coupon_count" sign:"true"`
	CouponFee     string   `xml:"coupon_fee" sign:"true"`
	DeviceInfo    string   `xml:"device_info" sign:"true"`
	ErrCode       string   `xml:"err_code" sign:"true"`
	ErrCodeDes    string   `xml:"err_code_des" sign:"true"`
	FeeType       string   `xml:"fee_type" sign:"true"`
	IsSubScribe   string   `xml:"is_subscribe" sign:"true"` //Y or N
	MchId         string   `xml:"mch_id" sign:"true"`
	NonceStr      string   `xml:"nonce_str" sign:"true"`
	OpenId        string   `xml:"openid" sign:"true"`
	OutTradeNo    string   `xml:"out_trade_no" sign:"true"`
	ResultCode    string   `xml:"result_code" sign:"true"` //SUCCESS or FAIL
	ReturnCode    string   `xml:"return_code" sign:"true"` //SUCCESS or FAIL
	ReturnMsg     string   `xml:"return_msg" sign:"true"`  //返回信息，如非空，为错误原因
	Sign          string   `xml:"sign" sign:"false"`       //sign=false表示不参与签名
	TimeEnd       string   `xml:"time_end" sign:"true"`
	TotalFee      string   `xml:"total_fee" sign:"true"`
	TradeType     string   `xml:"trade_type" sign:"true"` //JSAPI、NATIVE、APP
	TransactionId string   `xml:"transaction_id" sign:"true"`
}

func (this WXPayResultNotifyArgs) String() string {
	d, err := xml.Marshal(this)
	if err != nil {
		return err.Error()
	}
	return string(d)
}

//签名校验
func (this WXPayResultNotifyArgs) SignValid() bool {
	sign := WXSign(this)
	return sign == this.Sign
}

//nil表示没有错误
func (this WXPayResultNotifyArgs) IsError() error {
	if this.ReturnCode != SUCCESS {
		return errors.New(this.ReturnMsg)
	}
	if this.ResultCode != SUCCESS {
		return errors.New(fmt.Sprintf("ERROR:%d,%s", this.ErrCode, this.ErrCodeDes))
	}
	if !this.SignValid() {
		return errors.New("sign valid error")
	}
	return nil
}

//商户处理后返回格式
type WXPayResultResponse struct {
	xweb.XMLModel `xml:"-"`
	XMLName       struct{} `xml:"xml"`                   //root node name
	ReturnCode    string   `xml:"return_code,omitempty"` //SUCCESS or FAIL
	ReturnMsg     string   `xml:"return_msg,omitempty"`  //OK
}

func (this WXPayResultResponse) ToXML() string {
	data, err := xml.Marshal(this)
	if err != nil {
		panic(err)
	}
	return string(data)
}

type WXConfigForJS struct {
	Debug     bool     `json:"debug" sign:"false"`
	AppId     string   `json:"appId" sign:"false"`
	Timestamp string   `json:"timestamp" sign:"true"`
	NonceStr  string   `json:"nonceStr" sign:"true"`
	Signature string   `json:"signature" sign:"false"`
	JSApiList []string `json:"jsApiList" sign:"false"`
}

func (this WXConfigForJS) ToScript(jsticket string, url string) (template.JS, error) {
	this.AppId = WX_PAY_CONFIG.APP_ID
	this.Timestamp = TimeNowString()
	this.NonceStr = RandStr()
	if this.JSApiList == nil {
		this.JSApiList = []string{}
	}
	v := WXParseSignFields(this)
	v.Set("jsapi_ticket", jsticket)
	v.Set("url", url)
	this.Signature = xweb.SHA1String(v.RawEncode())
	data, err := json.Marshal(this)
	if err != nil {
		return template.JS(""), err
	}
	return template.JS(data), nil
}

//为jsapi支付返回给客户端用于客户端发起支付
type WXPayReqForJS struct {
	AppId     string `json:"appId,omitempty" sign:"true"`
	Timestamp int64  `json:"timeStamp,omitempty" sign:"true"`
	Package   string `json:"package,omitempty" sign:"true"`
	NonceStr  string `json:"nonceStr,omitempty" sign:"true"`
	SignType  string `json:"signType,omitempty" sign:"true"`
	PaySign   string `json:"paySign,omitempty" sign:"false"`
}

type WXPayReqScript struct {
	Timestamp int64  `json:"timestamp,omitempty"`
	Package   string `json:"package,omitempty"`
	NonceStr  string `json:"nonceStr,omitempty"`
	SignType  string `json:"signType,omitempty"`
	PaySign   string `json:"paySign,omitempty"`
}

func (this WXPayReqForJS) ToScript() (template.JS, error) {
	s := WXPayReqScript{}
	s.NonceStr = this.NonceStr
	s.Package = this.Package
	s.PaySign = this.PaySign
	s.SignType = this.SignType
	s.Timestamp = this.Timestamp
	data, err := json.Marshal(s)
	if err != nil {
		return template.JS(""), err
	}
	return template.JS(data), nil
}

func NewWXPayReqScript(prepayid string) WXPayReqScript {
	d := WXPayReqForJS{}
	d.AppId = WX_PAY_CONFIG.APP_ID
	d.Package = "prepay_id=" + prepayid
	d.NonceStr = RandStr()
	d.Timestamp = TimeNow()
	d.SignType = "MD5"
	d.PaySign = WXSign(d)
	s := WXPayReqScript{}
	s.NonceStr = d.NonceStr
	s.Package = d.Package
	s.PaySign = d.PaySign
	s.SignType = d.SignType
	s.Timestamp = d.Timestamp
	return s
}

//新建jsapi支付返回
func NewWXPayReqForJS(prepayid string) WXPayReqForJS {
	d := WXPayReqForJS{}
	d.AppId = WX_PAY_CONFIG.APP_ID
	d.Package = "prepay_id=" + prepayid
	d.NonceStr = RandStr()
	d.Timestamp = TimeNow()
	d.SignType = "MD5"
	d.PaySign = WXSign(d)
	return d
}

//为app支付返回给客户端用于客户端发起支付
type WXPayReqForApp struct {
	AppId     string `json:"appid,omitempty" sign:"true"`
	NonceStr  string `json:"noncestr,omitempty" sign:"true"`
	Package   string `json:"package,omitempty" sign:"true"` //APP支付固定(Sign=WXPay)
	PartnerId string `json:"partnerid,omitempty" sign:"true"`
	PrepayId  string `json:"prepayid,omitempty" sign:"true"` //统一下单返回
	Sign      string `json:"sign,omitempty" sign:"false"`
	Timestamp int64  `json:"timestamp,omitempty" sign:"true"`
}

func (this WXPayReqForApp) String() string {
	data, err := json.Marshal(this)
	if err != nil {
		return err.Error()
	}
	return string(data)
}

//新建APP支付返回
func NewWXPayReqForApp(prepayid string) WXPayReqForApp {
	d := WXPayReqForApp{}
	d.AppId = WX_PAY_CONFIG.APP_ID
	d.PrepayId = prepayid
	d.PartnerId = WX_PAY_CONFIG.MCH_ID
	d.Package = "Sign=WXPay"
	d.NonceStr = RandStr()
	d.Timestamp = TimeNow()
	d.Sign = WXSign(d)
	return d
}

//微信支付:统一下单
//https://api.mch.weixin.qq.com/pay/unifiedorder
type WXUnifiedorderRequest struct {
	XMLName        struct{} `xml:"xml"` //root node name
	AppId          string   `xml:"appid,omitempty" sign:"true"`
	Attach         string   `xml:"attach,omitempty" sign:"true"`
	Body           string   `xml:"body,omitempty" sign:"true"`
	Detail         string   `xml:"detail,omitempty" sign:"true"`
	DeviceInfo     string   `xml:"device_info,omitempty" sign:"true"`
	FeeType        string   `xml:"fee_type,omitempty" sign:"true"`
	GoodsTag       string   `xml:"goods_tag,omitempty" sign:"true"`
	LimitPay       string   `xml:"limit_pay,omitempty" sign:"true"`
	MchId          string   `xml:"mch_id,omitempty" sign:"true"`
	NonceStr       string   `xml:"nonce_str,omitempty" sign:"true"`
	NotifyURL      string   `xml:"notify_url,omitempty" sign:"true"`
	OpenId         string   `xml:"openid,omitempty" sign:"true"` //TradeType=TRADE_TYPE_JSAPI 必须
	OutTradeNo     string   `xml:"out_trade_no,omitempty" sign:"true"`
	ProductId      string   `xml:"product_id,omitempty" sign:"true"` //TradeType=TRADE_TYPE_NATIVE 必须
	Sign           string   `xml:"sign,omitempty"  sign:"false"`     //sign=false表示不参与签名
	SpBillCreateIp string   `xml:"spbill_create_ip,omitempty" sign:"true"`
	TimeExpire     string   `xml:"time_expire,omitempty" sign:"true"`
	TimeStart      string   `xml:"time_start,omitempty" sign:"true"`
	TotalFee       string   `xml:"total_fee,omitempty" sign:"true"`
	TradeType      string   `xml:"trade_type,omitempty" sign:"true"`
}

//微信支付:统一下单返回数据
type WXUnifiedorderResponse struct {
	XMLName    struct{} `xml:"xml"` //root node name
	AppId      string   `xml:"appid,omitempty" sign:"true"`
	CodeURL    string   `xml:"code_url,omitempty" sign:"true"` //trade_type=NATIVE返回code url
	DeviceInfo string   `xml:"device_info,omitempty" sign:"true"`
	ErrCode    string   `xml:"err_code,omitempty" sign:"true"`
	ErrCodeDes string   `xml:"err_code_des,omitempty" sign:"true"`
	MchId      string   `xml:"mch_id,omitempty" sign:"true"`
	NonceStr   string   `xml:"nonce_str,omitempty" sign:"true"`
	PrePayId   string   `xml:"prepay_id,omitempty" sign:"true"`
	ResultCode string   `xml:"result_code,omitempty" sign:"true"` //SUCCESS or FAIL
	ReturnCode string   `xml:"return_code,omitempty" sign:"true"` //SUCCESS or FAIL
	ReturnMsg  string   `xml:"return_msg,omitempty" sign:"true"`  //返回信息，如非空，为错误原因
	Sign       string   `xml:"sign,omitempty"  sign:"false"`      //sign=false表示不参与签名
	TradeType  string   `xml:"trade_type,omitempty" sign:"true"`
}

func (this WXUnifiedorderResponse) Error() error {
	if this.ReturnCode != SUCCESS {
		return errors.New("ERROR:" + this.ReturnMsg)
	}
	if this.ResultCode != SUCCESS {
		return errors.New("ERROR:" + this.ErrCode + "," + this.ErrCodeDes)
	}
	return nil
}

func (this WXUnifiedorderRequest) Post() (WXUnifiedorderResponse, error) {
	ret := WXUnifiedorderResponse{}
	if this.TotalFee == "" {
		panic(errors.New("TotalFee must > 0 "))
	}
	this.NonceStr = RandStr()
	if this.NotifyURL == "" {
		panic(errors.New("NotifyURL miss"))
	}
	this.AppId = WX_PAY_CONFIG.APP_ID
	this.MchId = WX_PAY_CONFIG.MCH_ID
	if this.AppId == "" {
		panic(errors.New("AppId miss"))
	}
	if this.MchId == "" {
		panic(errors.New("MchId miss"))
	}
	if this.NotifyURL == "" {
		panic(errors.New("NotifyURL miss"))
	}
	if this.TradeType == "" {
		panic(errors.New("TradeType must set"))
	}
	if this.TradeType == TRADE_TYPE_JSAPI && this.OpenId == "" {
		panic(errors.New(TRADE_TYPE_JSAPI + " openid empty"))
	}
	if this.TradeType == TRADE_TYPE_NATIVE && this.ProductId == "" {
		panic(errors.New(TRADE_TYPE_NATIVE + " product_id empty"))
	}
	this.Sign = WXSign(this)
	http := xweb.NewHTTPClient(WX_PAY_HOST)
	res, err := http.Post("/pay/unifiedorder", "application/xml", strings.NewReader(this.ToXML()))
	if err != nil {
		return ret, err
	}
	if err := res.ToXml(&ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
	}
	return ret, nil
}

func (this WXUnifiedorderRequest) ToXML() string {
	data, err := xml.Marshal(this)
	if err != nil {
		panic(err)
	}
	return string(data)
}
