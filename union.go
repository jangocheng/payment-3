package payment

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cxuhua/xweb"
	"log"
	"net/url"
	"reflect"
	"strings"
)

//union
type UnionKeyConfig struct {
	MCH_ID       string //商户号 测试用: 777290058130633
	MCH_PRIVATE  string //商户私钥
	MCH_PUBLIC   string //商户公钥
	MCH_CERTID   string //商户公钥证书ID
	UNION_PUBLIC string //银联公钥
	UNION_CERTID string //银联公钥证书ID
}

var (
	UNION_CONFIG      UnionKeyConfig  = UnionKeyConfig{}
	UNION_MCH_PRIVATE *rsa.PrivateKey = nil
	UNION_MCH_PUBLIC  *rsa.PublicKey  = nil
	UNION_PUBLIC_KEY  *rsa.PublicKey  = nil
)

/*
APP交易请求地址:
https://101.231.204.80:5000/gateway/api/appTransReq.do
*/

const (
	UNION_HOST = "https://101.231.204.80:5000"
)

func InitUnionKey(conf UnionKeyConfig) {
	UNION_CONFIG = conf

	//加载商户私钥
	if block, _ := pem.Decode([]byte(UNION_CONFIG.MCH_PRIVATE)); block != nil {
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			panic(err)
		} else {
			UNION_MCH_PRIVATE = key
		}
	} else {
		panic("load MCH_PRIVATE failed")
	}
	//加载商户公钥
	if block, _ := pem.Decode([]byte(UNION_CONFIG.MCH_PUBLIC)); block != nil {
		if cer, err := x509.ParseCertificate(block.Bytes); err != nil {
			panic(err)
		} else {
			UNION_CONFIG.MCH_CERTID = fmt.Sprintf("%v", cer.SerialNumber)
			UNION_MCH_PUBLIC = cer.PublicKey.(*rsa.PublicKey)
		}
	} else {
		panic("load UNION_PUBLIC_KEY failed")
	}
	//加载UNION公钥
	if block, _ := pem.Decode([]byte(UNION_CONFIG.UNION_PUBLIC)); block != nil {
		if cer, err := x509.ParseCertificate(block.Bytes); err != nil {
			panic(err)
		} else {
			UNION_CONFIG.UNION_CERTID = fmt.Sprintf("%v", cer.SerialNumber)
			UNION_PUBLIC_KEY = cer.PublicKey.(*rsa.PublicKey)
		}
	} else {
		panic("load UNION_PUBLIC_KEY failed")
	}
}

//校验来自阿里的数据
func UnionRSAVerify(src string, sign string) error {
	src = xweb.SHA1String(src)
	h := crypto.SHA1.New()
	h.Write([]byte(src))
	hashed := h.Sum(nil)
	sign = strings.Replace(sign, " ", "+", -1)
	data, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		log.Println(sign)
		return err
	}
	err = rsa.VerifyPKCS1v15(UNION_PUBLIC_KEY, crypto.SHA1, hashed, data)
	if err != nil {
		return err
	}
	return nil
}

func UnionSHA1SignValues(http xweb.HTTPValues) string {
	str := xweb.SHA1String(http.RawEncode())
	h := crypto.SHA1.New()
	h.Write([]byte(str))
	hashed := h.Sum(nil)
	sign, err := UNION_MCH_PRIVATE.Sign(rand.Reader, hashed, crypto.SHA1)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sign)
}

func UnionSHA1Sign(v interface{}) string {
	http := UnionParseFields(v, true)
	return UnionSHA1SignValues(http)
}

func UnionParseFields(src interface{}, isSign bool) xweb.HTTPValues {
	values := xweb.NewHTTPValues()
	t := reflect.TypeOf(src)
	v := reflect.ValueOf(src)
	for i := 0; i < t.NumField(); i++ {
		tf := t.Field(i)
		if isSign && tf.Tag.Get("sign") != "true" {
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
		name := tf.Tag.Get("form")
		if name == "" {
			continue
		}
		values.Add(name, sv)
	}
	return values
}

type UnionConsumeResponse struct {
	MerId      string `form:"merId" sign:"true"`
	OrderId    string `form:"orderId" sign:"true"`
	Version    string `form:"version" sign:"true"`
	CertId     string `form:"certId" sign:"true"`
	Encoding   string `form:"encoding" sign:"true"`
	Signature  string `form:"signature" sign:"false"`
	RespMsg    string `form:"respMsg" sign:"true"`
	TxnType    string `form:"txnType" sign:"true"`
	RespCode   string `form:"respCode" sign:"true"`
	SignMethod string `form:"signMethod" sign:"true"`
	TxnTime    string `form:"txnTime" sign:"true"`
	AccessType string `form:"accessType" sign:"true"`
	BizType    string `form:"bizType" sign:"true"`
	TN         string `form:"tn" sign:"true"`
	TxnSubType string `form:"txnSubType" sign:"true"`
}

func (this UnionConsumeResponse) IsError() error {
	if this.RespCode != "00" {
		return errors.New(this.RespMsg)
	}
	http := UnionParseFields(this, true)
	if err := UnionRSAVerify(http.RawEncode(), this.Signature); err != nil {
		return err
	}
	return nil
}

//消费请求
type UnionConsumeRequest struct {
	//基本字段
	Version     string `form:"version" sign:"true"`     //版本号固定填写5.0.0
	Encoding    string `form:"encoding" sign:"true"`    //编码方式	支持UTF-8与GBK
	CertId      string `form:"certId" sign:"true"`      //证书ID,填写签名私钥证书的Serial Number
	SignMethod  string `form:"signMethod" sign:"true"`  //01：表示采用RSA	固定填写01
	Signature   string `form:"signature" sign:"false"`  //签名
	TxnType     string `form:"txnType" sign:"true"`     //交易类型 01：消费 固定填写01
	TxnSubType  string `form:"txnSubType" sign:"true"`  //交易子类		固定填写01
	BizType     string `form:"bizType" sign:"true"`     //8	产品类型 固定填写000201
	ChannelType string `form:"channelType" sign:"true"` //9	渠道类型	固定填写08
	//商户信息
	AccessType string `form:"accessType" sign:"true"` //固定填写0
	MerId      string `form:"merId" sign:"true"`      //商户ID
	BackUrl    string `form:"backUrl" sign:"true"`    //通知url
	//订单信息
	OrderId      string `form:"orderId" sign:"true"`      //商户订单号，仅能用大小写字母与数字，不能用特殊字符
	CurrencyCode string `form:"currencyCode" sign:"true"` // 固定156
	TxnAmt       string `form:"txnAmt" sign:"true"`       //单位为分，不能带小数点例：1元填写100
	TxnTime      string `form:"txnTime" sign:"true"`      //YYYYMMDDHHmmss	,样例：20151123152540，北京时间	取当前时间，例：20151118100505
	PayTimeout   string `form:"payTimeout" sign:"true"`   //YYYYMMDDHHmmss
	AccNo        string `form:"accNo" sign:"true"`        //银行卡号。
	ReqReserved  string `form:"reqReserved" sign:"true"`  //ANS1..1024	O	商户自定义保留域，交易应答时会原样返回	商户自定义保留域，交易应答时会原样返回
	OrderDesc    string `form:"orderDesc" sign:"true"`    //ANS1..32
}

func (this UnionConsumeRequest) Post() error {
	this.Version = "5.0.0"
	this.Encoding = "UTF-8"
	this.CertId = UNION_CONFIG.MCH_CERTID
	this.SignMethod = "01"
	this.TxnType = "01"
	this.TxnSubType = "01"
	this.BizType = "000201"
	this.ChannelType = "08"
	this.AccessType = "0"
	this.MerId = UNION_CONFIG.MCH_ID
	if this.BackUrl == "" {
		panic(errors.New("backurl miss"))
	}
	if this.OrderId == "" {
		panic(errors.New("orderId miss"))
	}
	this.CurrencyCode = "156"
	if this.TxnAmt == "" {
		panic(errors.New("txnAmt miss"))
	}
	this.TxnTime = TimeString(0)
	this.PayTimeout = TimeString(60 * 30)
	this.Signature = UnionSHA1Sign(this)
	values := UnionParseFields(this, false)
	http := xweb.NewHTTPClient("https://101.231.204.80:5000")
	data, err := http.Post("/gateway/api/appTransReq.do", "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	uv, err := url.ParseQuery(string(data))
	if err != nil {
		return err
	}
	ret := UnionConsumeResponse{}
	xweb.MapFormType(&ret, uv, nil, nil)
	return ret.IsError()
}
