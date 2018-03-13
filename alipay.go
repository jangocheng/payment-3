package payment

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/cxuhua/xweb"
)

//alipay
type APKeyConfig struct {
	APP_ID              string //appid
	SIGN_TYPE           string //签名类型 RSA
	ALIPAY_KEY          string //阿里支付密钥
	PARTNET_PRIVATE_KEY string //商户私钥
	ALIPAY_PUBLIC_KEY   string //阿里支付公钥
	AP_PAY_NOTICE_URL   string //通知
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

func APSHA256Sign(v interface{}) string {
	http := APParseSignFields(v)
	str := http.RawEncode()
	h := crypto.SHA256.New()
	h.Write([]byte(str))
	hashed := h.Sum(nil)
	if s, err := rsa.SignPKCS1v15(rand.Reader, PARTNET_PRIVATE_KEY, crypto.SHA256, hashed); err != nil {
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
		tv := v.Field(i)
		if !tv.IsValid() {
			continue
		}
		sv := fmt.Sprintf("%v", tv.Interface())
		if sv == "" {
			continue
		}
		if tf.Tag.Get("sign") == "false" {
			continue
		}
		name := ""
		if xn := tf.Tag.Get("xml"); xn != "" {
			name = strings.Split(xn, ",")[0]
		} else if xn = tf.Tag.Get("json"); xn != "" {
			name = strings.Split(xn, ",")[0]
		} else if xn = tf.Tag.Get("form"); xn != "" {
			name = strings.Split(xn, ",")[0]
		} else {
			continue
		}
		//for xml
		ns := strings.Split(name, ">")
		if len(ns) > 0 {
			name = ns[len(ns)-1]
		} else {
			name = ns[0]
		}
		values.Add(name, sv)
	}
	return values
}

type APCommonRequest struct {
	AppId      string `json:"app_id"`            //是	32	支付宝分配给开发者的应用ID	2014072300007148
	Method     string `json:"method"`            //是	128	接口名称	alipay.trade.app.pay
	Format     string `json:"format"`            //否	40	仅支持JSON	JSON
	Charset    string `json:"charset"`           //是	10	请求使用的编码格式，如utf-8,gbk,gb2312等	utf-8
	SignType   string `json:"sign_type"`         //是	10	商户生成签名字符串所使用的签名算法类型，目前支持RSA2和RSA，推荐使用RSA2	RSA2
	Sign       string `json:"sign" sign:"false"` //是	256	商户请求参数的签名串，详见签名	详见示例
	Timestamp  string `json:"timestamp"`         //是	19	发送请求的时间，格式"yyyy-MM-dd HH:mm:ss"	2014-07-24 03:07:50
	Version    string `json:"version"`           //是	3	调用的接口版本，固定为：1.0	1.0
	NotifyURL  string `json:"notify_url"`        //是	256	支付宝服务器主动通知商户服务器里指定的页面http/https路径。建议商户使用https	https://api.xx.com/receive_notify.htm
	BizContent string `json:"biz_content"`       //是	-	业务请求参数的集合，最大长度不限，除公共参数外所有请求参数都必须放在这个参数中传递，具体参照各产品快速接入文档
}

func NewApCommonRequest(m string) APCommonRequest {
	req := APCommonRequest{}
	req.AppId = AP_PAY_CONFIG.APP_ID
	req.Method = m
	req.Format = "JSON"
	req.Charset = "utf-8"
	req.SignType = AP_PAY_CONFIG.SIGN_TYPE
	req.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	req.Version = "1.0"
	return req
}

//获取app支付字符串
func (this APCommonRequest) GetAppPayString() string {
	if this.NotifyURL == "" {
		panic(errors.New("NotifyURL miss"))
	}
	if this.BizContent == "" {
		panic(errors.New("BizContent miss"))
	}
	this.Sign = APSHA256Sign(this)
	rep := strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~")

	values := xweb.NewHTTPValues()
	t := reflect.TypeOf(this)
	v := reflect.ValueOf(this)
	for i := 0; i < t.NumField(); i++ {
		tf := t.Field(i)
		tv := v.Field(i)
		if !tv.IsValid() {
			continue
		}
		sv := fmt.Sprintf("%v", tv.Interface())
		if sv == "" {
			continue
		}
		name := tf.Tag.Get("json")
		if name == "" {
			continue
		}
		values.Add(name, sv)
	}
	return rep.Replace(values.Encode())
}

//校验来自阿里的数据
func APRSAVerify(src string, sign string) error {
	h := crypto.SHA256.New()
	h.Write([]byte(src))
	hashed := h.Sum(nil)
	data, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(ALIPAY_PUBLIC_KEY, crypto.SHA256, hashed, data)
}

//阿里支付请求参数
type APPayReqForApp struct {
	Body        string `json:"body,omitempty"`
	Subject     string `json:"subject,omitempty"`
	OutTradeNO  string `json:"out_trade_no,omitempty"`
	ProductCode string `json:"product_code"`
	TotalAmount string `json:"total_amount,omitempty"`
}

func (this APPayReqForApp) String() string {
	if this.OutTradeNO == "" {
		panic(errors.New("OutTradeNO miss"))
	}
	if this.Subject == "" {
		panic(errors.New("Subject miss"))
	}
	if this.TotalAmount == "" {
		panic(errors.New("TotalFee miss"))
	}
	if this.Body == "" {
		panic(errors.New("Body miss"))
	}
	biz, err := json.Marshal(this)
	if err != nil {
		panic(err)
	}
	//配置公共参数
	apc := NewApCommonRequest("alipay.trade.app.pay")
	apc.NotifyURL = AP_PAY_CONFIG.AP_PAY_NOTICE_URL
	apc.BizContent = string(biz)
	return apc.GetAppPayString()
}

func NewAPPayReqForApp() APPayReqForApp {
	d := APPayReqForApp{}
	d.ProductCode = "QUICK_MSECURITY_PAY"
	return d
}

//交易状态说明
const (
	NOTICE_SUCCESS = "success"        //处理成功返回给支付宝
	WAIT_BUYER_PAY = "WAIT_BUYER_PAY" //	交易创建，等待买家付款
	TRADE_CLOSED   = "TRADE_CLOSED"   //	未付款交易超时关闭，或支付完成后全额退款
	TRADE_SUCCESS  = "TRADE_SUCCESS"  //	交易支付成功
	TRADE_FINISHED = "TRADE_FINISHED" //	交易结束，不可退款
)

//支付宝回调参数结构
/*
{
	"app_id": ["2018012202022468"],
	"auth_app_id": ["2018012202022468"],
	"body": ["礼盒订单"],
	"buyer_id": ["2088702869339810"],
	"buyer_logon_id": ["315***@qq.com"],
	"buyer_pay_amount": ["0.01"],
	"charset": ["utf-8"],
	"fund_bill_list": ["[{\"amount\":\"0.01\",\"fundChannel\":\"ALIPAYACCOUNT\"}]"],
	"gmt_create": ["2018-03-13 13:55:52"],
	"gmt_payment": ["2018-03-13 13:55:53"],
	"invoice_amount": ["0.01"],
	"notify_id": ["7e6ec782c2c96187a08d8b583b4f17em95"],
	"notify_time": ["2018-03-13 13:55:53"],
	"notify_type": ["trade_status_sync"],
	"out_trade_no": ["5aa6320fc0b6fa10282306b2"],
	"point_amount": ["0.00"],
	"receipt_amount": ["0.01"],
	"seller_email": ["2885495633@qq.com"],
	"seller_id": ["2088921762100192"],
	"sign": ["HY106+s14EMDtvsdES8M6rcbpgRek6BWxfoP6b2E+DRRVld/Qv1Cq46NUeTG/Oiu9QspZga1IZfFMhU3wK1Z/sSKLW2nhdZbd2b1A1DLYz57DV7ezJJLGEkQgt6CWiwzADX0ccU6fH3Au5bEWAJ4JF+qlgVUg/4gtm1lO0Em+1lrFqf1dryLsdxXYXGJy0qQC9LZOcif69TCH9LtZAydYW4Qa656HNP06OlWTn8vSKNKdkmDIlixfv1g1PAtcfphG5Gjrg5ByyGWnGu/UIZCxGxkZPJID0+efCLsRjm9lkmbEmuhWE1YlVYejYEpToM77LOCaNKE7wYZ50y1CaOBrg=="],
	"sign_type": ["RSA2"],
	"subject": ["礼盒订单"],
	"total_amount": ["0.01"],
	"trade_no": ["2018031321001004810502093299"],
	"trade_status": ["TRADE_SUCCESS"],
	"version": ["1.0"]
}
*/
type APNotifyMessage struct {
	NotifyTime        string `form:"notify_time"`
	NotifyType        string `form:"notify_type"`
	NotifyId          string `form:"notify_id"`
	AppId             string `form:"app_id"`
	AuthAppId         string `form:"auth_app_id"`
	Charset           string `form:"charset"`
	Version           string `form:"version"`
	SignType          string `form:"sign_type" sign:"false"`
	Sign              string `form:"sign" sign:"false"`
	TradeNo           string `form:"trade_no"`
	OutTradeNo        string `form:"out_trade_no"`
	OutBizNo          string `form:"out_biz_no"`
	BuyerId           string `form:"buyer_id"`
	BuyerLogonId      string `form:"buyer_logon_id"`
	SellerId          string `form:"seller_id"`
	SellerEmail       string `form:"seller_email"`
	TradeStatus       string `form:"trade_status"`
	TotalAmount       string `form:"total_amount"`
	ReceiptAmount     string `form:"receipt_amount"`
	InvoiceAmount     string `form:"invoice_amount"`
	BuyerPayAmount    string `form:"buyer_pay_amount"`
	PointAmount       string `form:"point_amount"`
	RefundFee         string `form:"refund_fee"`
	Subject           string `form:"subject"`
	Body              string `form:"body"`
	GMTCreate         string `form:"gmt_create"`
	GMTPayment        string `form:"gmt_payment"`
	GMTRefund         string `form:"gmt_refund"`
	GMTClose          string `form:"gmt_close"`
	FundBillList      string `form:"fund_bill_list"`
	PassbackParams    string `form:"passback_params"`
	VoucherDetailList string `form:"voucher_detail_list"`
}

//支付是否成功
func (this APNotifyMessage) IsSuccess() bool {
	if this.AppId != AP_PAY_CONFIG.APP_ID {
		return false
	}
	if this.TradeStatus != TRADE_SUCCESS && this.TradeStatus != TRADE_FINISHED {
		return false
	}
	return this.IsValid()
}

//签名校验
func (this APNotifyMessage) IsValid() bool {
	v := APParseSignFields(this)
	s := v.RawEncode()
	if err := APRSAVerify(s, this.Sign); err != nil {
		log.Println(err)
		return false
	}
	return true
}
