package payment

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	// "encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cxuhua/xweb"
	"net/url"
	"reflect"
	"strings"
)

//alipay
type APKeyConfig struct {
	PARTNER_ID          string `json:"partnetId"`         //商户id
	SELLER_EMAIL        string `json:"sellerEmail"`       //商户支付email
	SIGN_TYPE           string `json:"signType"`          //签名类型 RSA
	ALIPAY_KEY          string `json:"alipayKey"`         //阿里支付密钥
	PARTNET_PRIVATE_KEY string `json:"partnerPrivateKey"` //商户私钥
	ALIPAY_PUBLIC_KEY   string `json:"alipayPublicKey"`   //阿里支付公钥
}

var (
	AP_PAY_CONFIG       APKeyConfig     = APKeyConfig{}
	PARTNET_PRIVATE_KEY *rsa.PrivateKey = nil
	ALIPAY_PUBLIC_KEY   *rsa.PublicKey  = nil
)

func InitAPKey(conf APKeyConfig) {
	AP_PAY_CONFIG = conf
	//加载商户私钥
	if block, _ := pem.Decode([]byte(AP_PAY_CONFIG.PARTNET_PRIVATE_KEY)); block != nil {
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			panic(err)
		} else {
			PARTNET_PRIVATE_KEY = key
		}
	} else {
		panic("load PARTNET_PRIVATE_KEY failed")
	}
	//加载支付宝公钥
	if block, _ := pem.Decode([]byte(AP_PAY_CONFIG.ALIPAY_PUBLIC_KEY)); block != nil {
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			panic(err)
		} else {
			ALIPAY_PUBLIC_KEY = pub.(*rsa.PublicKey)
		}
	} else {
		panic("load ALIPAY_PUBLIC_KEY failed")
	}
}

func APSign(v interface{}) string {
	http := APParseSignFields(v)
	str := http.RawEncode()
	h := crypto.SHA1.New()
	h.Write([]byte(str))
	hashed := h.Sum(nil)
	if s, err := rsa.SignPKCS1v15(rand.Reader, PARTNET_PRIVATE_KEY, crypto.SHA1, hashed); err != nil {
		panic(err)
	} else {
		return base64.StdEncoding.EncodeToString(s)
	}
}

func APParseSignFields(src interface{}) xweb.HTTPValues {
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

//校验来自阿里的数据
func ALRSAVerify(src string, sign string) (pass bool, err error) {
	digest := xweb.SHA1String(src)
	data, _ := base64.StdEncoding.DecodeString(sign)
	err = rsa.VerifyPKCS1v15(ALIPAY_PUBLIC_KEY, crypto.SHA1, []byte(digest), []byte(data))
	if err != nil {
		return false, err
	}
	return true, nil
}

/*
TradeStatus
WAIT_BUYER_PAY	交易创建，等待买家付款。
TRADE_CLOSED	在指定时间段内未支付时关闭的交易；在交易完成全额退款成功时关闭的交易。
TRADE_SUCCESS	交易成功，且可对该交易做操作，如：多级分润、退款等。
TRADE_FINISHED	交易成功且结束，即不可再做任何操作。
*/

//支付宝服务器异步通知参数说明
type APPayResultNotifyArgs struct {
	xweb.FORMArgs
	NotifyTime   string `form:"notify_time" sign:"true"`
	NotifyType   string `form:"notify_type" sign:"true"`
	NotifyId     string `form:"notify_id" sign:"true"`
	SignType     string `form:"sign_type" sign:"false"` //RSA
	Sign         string `form:"sign" sign:"false"`
	OutTradeNO   string `form:"out_trade_no" sign:"true"`
	Subject      string `form:"subject" sign:"true"`
	PaymentType  string `form:"payment_type" sign:"true"` //1
	TradeNO      string `form:"trade_no" sign:"true"`
	TradeStatus  string `form:"trade_status" sign:"true"`
	SellerId     string `form:"seller_id" sign:"true"`
	SellerEmail  string `form:"seller_email" sign:"true"`
	BuyerId      string `form:"buyer_id" sign:"true"`
	BuyerEmail   string `form:"buyer_email" sign:"true"`
	TotalFee     string `form:"total_fee" sign:"true"`
	Quantity     string `form:"quantity" sign:"true"`
	Price        string `form:"price" sign:"true"`
	Body         string `form:"body" sign:"true"`
	GMTCreate    string `form:"gmt_create" sign:"true"`
	GMTPayment   string `form:"gmt_payment" sign:"true"`
	FeeAdjust    string `form:"is_total_fee_adjust" sign:"true"`
	UseCoupon    string `form:"use_coupon" sign:"true"`
	Discount     string `form:"discount" sign:"true"`
	RefundStatus string `form:"refund_status" sign:"true"`
	GMTRefund    string `form:"gmt_refund" sign:"true"`
}

//阿里支付请求参数
type APPayReqForApp struct {
	Service      string `json:"service,omitempty" sign:"true"`
	Partner      string `json:"partner,omitempty" sign:"true"`
	InputCharset string `json:"_input_charset,omitempty" sign:"true"`
	SignType     string `json:"sign_type,omitempty" sign:"false"`
	Sign         string `json:"sign,omitempty" sign:"false"`
	NotifyURL    string `json:"notify_url,omitempty" sign:"true"`
	OutTradeNO   string `json:"out_trade_no,omitempty" sign:"true"`
	Subject      string `json:"subject,omitempty" sign:"true"`
	PaymentType  string `json:"payment_type,omitempty" sign:"true"`
	SellerId     string `json:"seller_id,omitempty" sign:"true"`
	TotalFee     string `json:"total_fee,omitempty" sign:"true"`
	Body         string `json:"body,omitempty" sign:"true"`
}

func (this APPayReqForApp) String() string {
	if this.NotifyURL == "" {
		panic(errors.New("NotifyURL miss"))
	}
	if this.OutTradeNO == "" {
		panic(errors.New("OutTradeNO miss"))
	}
	if this.Subject == "" {
		panic(errors.New("Subject miss"))
	}
	if this.TotalFee == "" {
		panic(errors.New("TotalFee miss"))
	}
	if this.Body == "" {
		panic(errors.New("Body miss"))
	}
	this.Sign = url.QueryEscape(APSign(this))
	values := xweb.NewHTTPValues()
	t := reflect.TypeOf(this)
	v := reflect.ValueOf(this)
	for i := 0; i < t.NumField(); i++ {
		tf := t.Field(i)
		tv := v.Field(i)
		if !tv.IsValid() {
			continue
		}
		jt := strings.Split(tf.Tag.Get("json"), ",")
		if len(jt) == 0 || jt[0] == "" {
			continue
		}
		sv := fmt.Sprintf(`%v`, tv.Interface())
		if sv == "" {
			continue
		}
		values.Add(jt[0], sv)
	}
	return values.RawEncode()
}

func NewAPPayReqForApp() APPayReqForApp {
	d := APPayReqForApp{}
	d.Service = "mobile.securitypay.pay"
	d.Partner = AP_PAY_CONFIG.PARTNER_ID
	d.InputCharset = "utf-8"
	d.SignType = "RSA"
	d.PaymentType = "1"
	d.SellerId = AP_PAY_CONFIG.SELLER_EMAIL
	return d
}
