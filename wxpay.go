package payment

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/cxuhua/xweb"
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
	APP_ID     string `json:"appId"`
	APP_SECRET string `json:"appSecret"`
	MCH_ID     string `json:"mchId"`
	MCH_KEY    string `json:"mchKey"`
}

var (
	WX_PAY_CONFIG     WXKeyConfig = WXKeyConfig{}
	WX_PAY_NOTIFY_URL             = "http://pay_notify_url.com"
)

func InitWXKey(conf WXKeyConfig) {
	WX_PAY_CONFIG = conf
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

//返回字符串
const (
	SUCCESS = "SUCCESS"
	FAIL    = "FAIL"
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
	return errors.New(fmt.Sprintf("ERROR:%d,%s", this.ErrCode, this.ErrMsg))
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
	data, err := http.Get("/sns/oauth2/access_token", v)
	if err != nil {
		return ret, err
	}
	if err = json.Unmarshal(data, &ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
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
	data, err := http.Get("/sns/oauth2/refresh_token", v)
	if err != nil {
		return ret, err
	}
	if err = json.Unmarshal(data, &ret); err != nil {
		return ret, err
	}
	if err := ret.Error(); err != nil {
		return ret, err
	}
	return ret, nil
}

//拉取用户信息
//https://api.weixin.qq.com/sns/userinfo
type WXUserInfoRequest struct {
	AccessToken string `json:"access_token" sign:"true"`
	OpenId      string `json:"openid" sign:"true"`
	Lang        string `json:"lang" sign:"true"`
}

type WXUserInfoResponse struct {
	WXError
	OpenId     string   `json:"openid"`
	NickName   string   `json:"nickname"`
	Sex        string   `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgURL string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	UnionId    string   `json:"unionid"`
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
	data, err := http.Get("/sns/userinfo", v)
	if err != nil {
		return ret, err
	}
	if err = json.Unmarshal(data, &ret); err != nil {
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
	data, err := http.Get("/sns/auth", v)
	if err != nil {
		ret.ErrCode = 1000000
		ret.ErrMsg = err.Error()
	} else if err = json.Unmarshal(data, &ret); err != nil {
		ret.ErrCode = 1000001
		ret.ErrMsg = err.Error()
	}
	return ret
}

//支付结果通用通知
//微信服务器将会根据统一下单的NotifyURL POST以下数据到商机服务器处理
type WXPayResultNotifyArgs struct {
	xweb.XMLArgs
	XMLName       struct{} `xml:"xml"`                     //root node name
	ReturnCode    string   `xml:"return_code" sign:"true"` //SUCCESS or FAIL
	ReturnMsg     string   `xml:"return_msg" sign:"true"`  //返回信息，如非空，为错误原因
	AppId         string   `xml:"appid" sign:"true"`
	MchId         string   `xml:"mch_id" sign:"true"`
	DeviceInfo    string   `xml:"device_info" sign:"true"`
	NonceStr      string   `xml:"nonce_str" sign:"true"`
	Sign          string   `xml:"sign" sign:"false"`       //sign=false表示不参与签名
	ResultCode    string   `xml:"result_code" sign:"true"` //SUCCESS or FAIL
	ErrCode       string   `xml:"err_code" sign:"true"`
	ErrCodeDes    string   `xml:"err_code_des" sign:"true"`
	OpenId        string   `xml:"openid" sign:"true"`
	IsSubScribe   string   `xml:"is_subscribe" sign:"true"` //Y or N
	TradeType     string   `xml:"trade_type" sign:"true"`   //JSAPI、NATIVE、APP
	BankType      string   `xml:"bank_type" sign:"true"`
	TotalFee      string   `xml:"total_fee" sign:"true"`
	FeeType       string   `xml:"fee_type" sign:"true"`
	CashFee       string   `xml:"cash_fee" sign:"true"`
	CashFeeType   string   `xml:"cash_fee_type" sign:"true"`
	TransactionId string   `xml:"transaction_id" sign:"true"`
	OutTradeNo    string   `xml:"out_trade_no" sign:"true"`
	Attach        string   `xml:"attach" sign:"true"`
	TimeEnd       string   `xml:"time_end" sign:"true"`
	CouponFee     string   `xml:"coupon_fee" sign:"true"`
	CouponCount   string   `xml:"coupon_count" sign:"true"`
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
	XMLName    struct{} `xml:"xml"`                   //root node name
	ReturnCode string   `xml:"return_code,omitempty"` //SUCCESS or FAIL
	ReturnMsg  string   `xml:"return_msg,omitempty"`  //OK
}

func (this WXPayResultResponse) ToXML() string {
	data, err := xml.Marshal(this)
	if err != nil {
		panic(err)
	}
	return string(data)
}

//为jsapi支付返回给客户端用于客户端发起支付
type WXPayReqForJS struct {
	AppId     string `json:"appId,omitempty" sign:"true"`
	Timestamp string `json:"timeStamp,omitempty" sign:"true"`
	Package   string `json:"package,omitempty" sign:"true"`
	NonceStr  string `json:"nonceStr,omitempty" sign:"true"`
	SignType  string `json:"signType,omitempty" sign:"true"`
	PaySign   string `json:"paySign,omitempty" sign:"false"`
}

//新建jsapi支付返回
func NewWXPayReqForJS(prepayid string) WXPayReqForJS {
	d := WXPayReqForJS{}
	d.AppId = WX_PAY_CONFIG.APP_ID
	d.Package = "prepay_id=" + prepayid
	d.NonceStr = RandStr()
	d.Timestamp = TimeString(0)
	d.SignType = "MD5"
	d.PaySign = WXSign(d)
	return d
}

//为app支付返回给客户端用于客户端发起支付
type WXPayReqForApp struct {
	AppId     string `json:"appid,omitempty" sign:"true"`
	PartnerId string `json:"partnerid,omitempty" sign:"true"`
	PrepayId  string `json:"prepayid,omitempty" sign:"true"` //统一下单返回
	Package   string `json:"package,omitempty" sign:"true"`  //APP支付固定(Sign=WXPay)
	NonceStr  string `json:"noncestr,omitempty" sign:"true"`
	Timestamp int64  `json:"timestamp,omitempty" sign:"true"`
	Sign      string `json:"sign,omitempty" sign:"false"`
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
	MchId          string   `xml:"mch_id,omitempty" sign:"true"`
	DeviceInfo     string   `xml:"device_info,omitempty" sign:"true"`
	NonceStr       string   `xml:"nonce_str,omitempty" sign:"true"`
	Sign           string   `xml:"sign,omitempty"  sign:"false"` //sign=false表示不参与签名
	Body           string   `xml:"body,omitempty" sign:"true"`
	Detail         string   `xml:"detail,omitempty" sign:"true"`
	Attach         string   `xml:"attach,omitempty" sign:"true"`
	OutTradeNo     string   `xml:"out_trade_no,omitempty" sign:"true"`
	FeeType        string   `xml:"fee_type,omitempty" sign:"true"`
	TotalFee       string   `xml:"total_fee,omitempty" sign:"true"`
	SpBillCreateIp string   `xml:"spbill_create_ip,omitempty" sign:"true"`
	TimeStart      string   `xml:"time_start,omitempty" sign:"true"`
	TimeExpire     string   `xml:"time_expire,omitempty" sign:"true"`
	GoodsTag       string   `xml:"goods_tag,omitempty" sign:"true"`
	NotifyURL      string   `xml:"notify_url,omitempty" sign:"true"`
	TradeType      string   `xml:"trade_type,omitempty" sign:"true"`
	LimitPay       string   `xml:"limit_pay,omitempty" sign:"true"`
	ProductId      string   `xml:"product_id,omitempty" sign:"true"` //TradeType=TRADE_TYPE_NATIVE 必须
	OpenId         string   `xml:"openid,omitempty" sign:"true"`     //TradeType=TRADE_TYPE_JSAPI 必须
}

//微信支付:统一下单返回数据
type WXUnifiedorderResponse struct {
	XMLName    struct{} `xml:"xml"`                               //root node name
	ReturnCode string   `xml:"return_code,omitempty" sign:"true"` //SUCCESS or FAIL
	ReturnMsg  string   `xml:"return_msg,omitempty" sign:"true"`  //返回信息，如非空，为错误原因
	AppId      string   `xml:"appid,omitempty" sign:"true"`
	MchId      string   `xml:"mch_id,omitempty" sign:"true"`
	DeviceInfo string   `xml:"device_info,omitempty" sign:"true"`
	NonceStr   string   `xml:"nonce_str,omitempty" sign:"true"`
	Sign       string   `xml:"sign,omitempty"  sign:"false"`      //sign=false表示不参与签名
	ResultCode string   `xml:"result_code,omitempty" sign:"true"` //SUCCESS or FAIL
	ErrCode    string   `xml:"err_code,omitempty" sign:"true"`
	ErrCodeDes string   `xml:"err_code_des,omitempty" sign:"true"`
	TradeType  string   `xml:"trade_type,omitempty" sign:"true"`
	PrePayId   string   `xml:"prepay_id,omitempty" sign:"true"`
	CodeURL    string   `xml:"code_url,omitempty" sign:"true"` //trade_type=NATIVE返回code url
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
	this.NotifyURL = WX_PAY_NOTIFY_URL
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
	if WX_PAY_CONFIG.MCH_KEY == "" {
		panic(errors.New("MchKey miss"))
	}
	this.Sign = WXSign(this)
	http := xweb.NewHTTPClient(WX_PAY_HOST)
	data, err := http.Post("/pay/unifiedorder", "application/xml", strings.NewReader(this.ToXML()))
	if err != nil {
		return ret, err
	}
	if err = xml.Unmarshal(data, &ret); err != nil {
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
