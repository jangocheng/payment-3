package payment

import (
	// "crypto/aes"
	// "crypto/cipher"
	// "encoding/base64"
	// "github.com/cxuhua/xweb"
	"log"
	"testing"
)

func TestWXAppGetOpenId(t *testing.T) {

	WX_PAY_CONFIG.APP_ID = "wx69bff98e03bdadb4"
	WX_PAY_CONFIG.APP_SECRET = "474af7364fcdc681d5d1b2607f622521"

	// res1, err := WXGetAccessToken()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// log.Println(res1)

	// s := `UmQIEHpaqBbDvwm35CoQnfZrQaL5JO5Hvuw7sQk2hmwFPEpRjPV3VA6rMX1W1pH23pbwzhNb+JchirCyjm9IVbjoEuH5mCO8+kzMiVpcbgVoyIcfP+eP6zTLau+S0bHVIXfJXTv4DGdV+yUmo02vdR2E+lnlV47c/H9XABei/h6M/QNPliGYvZTEJmbkoaVOY/FwbP1XJbaCKCzQOk7PgSvsqeUAsthnpw2rZGEH8H+zoT6jmyENpjnA4jA8dc4hcZxY3AODP5tqOtp8ISPwkJrMssxyXa56HCisdmyaXWlySdtqzgkAHsYnCU34mCAuqWqiS9zK/30bQo5KlSBFRiMBCuv2gk+1evqcQQbD55Zk62yQOu6KhMe1TbOa5YDyb7FHnVLo4lfTF9ZI5TUILc4yMEX89wgvyXCAFM/AqsJsbQ/BRpvDmp4c2dwAGIXWNzVFLHV2dlCViwAAYMrrlXiCAmsRh3B9pPl9vHtc8iA=`

	s := "X0DsgCvFbgv1btz6BAMBgvZBxMWKf3VYtbpFiEua+wWkkI15/FhWaGSz38p6gCaLIy6/1GDFUkqcXeliyMpTYkwdocoYUlmaLFWHXGVjCH8TjpA4pmCm6zp/KxhvSn/iIMR2xIuCiOdoivtbvHIemXm9g/bwrzLT8kEuIE/SnOdbXhhxdKhfiQPya1cPzapfKaqHI0r7p1OnEBj59o/L3Jl2054UV+TDLxIWPJpKTvzyxKg8/p2O7UCN5MT/iYTSVr8bRk2OWgbRnJGBsknYvXxwOhcJGHf2fQ4I9ZbVGc565uVk3Wtp2etVGo5jJ8dY7IRB0H9K9/EaaNPDZRkjUk0YK226Nqlno4Gxr3TqDcyVZLpFs0HrfIRQKB6mOLaOO33ba0pnPEHAIi+tdhpp9I4NZD8wdcqMXq1AmMw93chJww7RyrUm6Ku0wtKxZbG/ZPN4+EXNqLdVBJ8KIdj+u5aAkqhNj1G9wP+uW/Pt5Eg="
	iv := "EUZ/7dH5F41dUViVVLY73w=="
	sessionKey := "OXEqIUKiWhsuY3mLJLudsQ=="

	log.Println(WXAppDecodeEncryptedData(sessionKey, iv, s))

	// // res2, err := WXAppGetSessionKey(code)
	// // if err != nil {
	// // 	t.Fatal(err)
	// // }
	// // log.Println("sessionKey", res2.SessionKey)
	// data, err := base64.StdEncoding.DecodeString(s)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// log.Println("data", data)
	// aesKey, err := base64.StdEncoding.DecodeString(sessionKey)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// log.Println("aesKey", aesKey)
	// ivdata, err := base64.StdEncoding.DecodeString(iv)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// log.Println("ivdata", ivdata)

	// aes, _ := xweb.NewAESChpher(aesKey)
	// d, err := xweb.AesDecryptWithIV(aes, data, ivdata)

	// log.Println(string(d), err)

	// log.Println(res2.OpenId)
	// log.Println(res2.SessionKey)

	// uq := WXUserInfoRequest{}
	// uq.AccessToken = res1.AccessToken
	// uq.OpenId = res2.OpenId
	// res3, err := uq.Get()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// log.Println(res3)
}

// func TestUnion(t *testing.T) {
// 	conf := UnionKeyConfig{}
// 	conf.MCH_ID = "777290058130633"
// 	conf.UNION_HOST = "https://101.231.204.80:5000"
// 	conf.MCH_PRIVATE = `
// -----BEGIN RSA PRIVATE KEY-----
// MIICXAIBAAKBgQCQvyFGMGkKxojiX2VUkXvu6mNJk/ayHRHXo7KOxC3oQE+QZPk2
// 4MnBT5eqn7pmxxkZ2Ky5NKCN914LEPJ+6+XatDEIxU7ZXDHQuGa6/Q5W35lh9aC+
// M7ULZ8eWjIKM+zlnS5MrUOML8EpvoETCnC2V3YfgM45tTIXEEo3Dkx5RWwIDAQAB
// AoGAP9F1OzwW5CBas+w5ggrO6KzA7+zj5O36MuhCzr1iPDc2nURXuMFtUuTjyt+3
// 0J7Ry1qD9PhmHZHGDfz/3cPmSFgxOmEkvc/xN0TGNfN+WZdcc/n16DKvOUXfEUE1
// nx0g6UPP3MI86TaIX+cmHFuSIfRgcFOj1+9xsx8DtYkVVZkCQQDICwzlq3eDw7N+
// zkBCie/UhvGOTxjPpZHyjaR3z9CWBETyzw3WM3pgBxFafYXo2ad7HUjYm7bCIM9b
// DB6DufrXAkEAuTxU7XnW8khKVqaszlerWE9ohhAgn6EMR4i3PcpYFF8rdz4AWQfn
// gdfhAo9UARW0gjOMe9evnBup7RLONMxxHQJBAJS5QnluJYjc8pIQHU5a5ueG/Afl
// Xnjii8Nc8y3wXw9pVSmALrVVyGGkX457TBd12kJ53zLLcfCaHA+Azx74IjkCQEKd
// uOlCpROy/dEV1hXLH5r9y9hS2niuAW2EdGnraCvDYi1bBeL+3boregdiplJRjP46
// La6oDca1iDHzTmdckt0CQFSu+N+zVpz582JcRO1VLSuQz9WDlivtlM8CJW4Xtoq1
// ceKDIbnYCkGWKyflpgI77cxgRzv9ph0vE4r9LmqUwsE=
// -----END RSA PRIVATE KEY-----
// `
// 	conf.MCH_PUBLIC = `
// -----BEGIN CERTIFICATE-----
// MIIDuzCCAySgAwIBAgIQHkJIM0PhX1NPZsjWiDSBzTANBgkqhkiG9w0BAQUFADAk
// MQswCQYDVQQGEwJDTjEVMBMGA1UEChMMQ0ZDQSBURVNUIENBMB4XDTE1MDcwMjA3
// MzEzNVoXDTE3MDcwMjA3MzEzNVowgYAxCzAJBgNVBAYTAkNOMRUwEwYDVQQKEwxD
// RkNBIFRFU1QgQ0ExDTALBgNVBAsTBEJPREwxFDASBgNVBAsTC0VudGVycHJpc2Vz
// MTUwMwYDVQQDFCwwNDFAWloyMDE1MDcwMkA3MDAwMDAwMDAwMDAwMDE6U0lHTkAw
// MDAwMDAwMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAkL8hRjBpCsaI4l9l
// VJF77upjSZP2sh0R16OyjsQt6EBPkGT5NuDJwU+Xqp+6ZscZGdisuTSgjfdeCxDy
// fuvl2rQxCMVO2Vwx0Lhmuv0OVt+ZYfWgvjO1C2fHloyCjPs5Z0uTK1DjC/BKb6BE
// wpwtld2H4DOObUyFxBKNw5MeUVsCAwEAAaOCAY8wggGLMB8GA1UdIwQYMBaAFEZy
// 3CVynwJOVYO1gPkL2+mTs/RFMB0GA1UdDgQWBBRGIxcZAOpI+tCDQp/ZCUmEEmTK
// tDALBgNVHQ8EBAMCBPAwDAYDVR0TBAUwAwEBADA7BgNVHSUENDAyBggrBgEFBQcD
// AQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwgfAGA1Ud
// HwSB6DCB5TBPoE2gS6RJMEcxCzAJBgNVBAYTAkNOMRUwEwYDVQQKEwxDRkNBIFRF
// U1QgQ0ExDDAKBgNVBAsTA0NSTDETMBEGA1UEAxMKY3JsMTI3XzM0MDCBkaCBjqCB
// i4aBiGxkYXA6Ly90ZXN0bGRhcC5jZmNhLmNvbS5jbjozODkvQ049Y3JsMTI3XzM0
// MCxPVT1DUkwsTz1DRkNBIFRFU1QgQ0EsQz1DTj9jZXJ0aWZpY2F0ZVJldm9jYXRp
// b25MaXN0P2Jhc2U/b2JqZWN0Y2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwDQYJ
// KoZIhvcNAQEFBQADgYEAG3yOv3LD+hYsXnHC5werUcrJbh409ZyVxaagYBl/OLoX
// 1r51xwp4U3RkPR7fGt9payv7gUOD9p5AVhAh4/UR4+LPQdfZqVMXEGF2f/sALXlI
// 6KyDp9ewMzm91N7ri0oZUgFl/Xu5rDgo/32pb0lWrMuhex7DX7cPI/qALVu/anw=
// -----END CERTIFICATE-----
// `
// 	conf.UNION_PUBLIC = `
// -----BEGIN CERTIFICATE-----
// MIIEOjCCAyKgAwIBAgIFEAJkAUkwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMC
// Q04xMDAuBgNVBAoTJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhv
// cml0eTEXMBUGA1UEAxMOQ0ZDQSBURVNUIE9DQTEwHhcNMTUxMjA0MDMyNTIxWhcN
// MTcxMjA0MDMyNTIxWjB5MQswCQYDVQQGEwJjbjEXMBUGA1UEChMOQ0ZDQSBURVNU
// IE9DQTExEjAQBgNVBAsTCUNGQ0EgVEVTVDEUMBIGA1UECxMLRW50ZXJwcmlzZXMx
// JzAlBgNVBAMUHjA0MUBaMTJAMDAwNDAwMDA6U0lHTkAwMDAwMDA2MjCCASIwDQYJ
// KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMUDYYCLYvv3c911zhRDrSWCedAYDJQe
// fJUjZKI2avFtB2/bbSmKQd0NVvh+zXtehCYLxKOltO6DDTRHwH9xfhRY3CBMmcOv
// d2xQQvMJcV9XwoqtCKqhzguoDxJfYeGuit7DpuRsDGI0+yKgc1RY28v1VtuXG845
// fTP7PRtJrareQYlQXghMgHFAZ/vRdqlLpVoNma5C56cJk5bfr2ngDlXbUqPXLi1j
// iXAFb/y4b8eGEIl1LmKp3aPMDPK7eshc7fLONEp1oQ5Jd1nE/GZj+lC345aNWmLs
// l/09uAvo4Lu+pQsmGyfLbUGR51KbmHajF4Mrr6uSqiU21Ctr1uQGkccCAwEAAaOB
// 6TCB5jAfBgNVHSMEGDAWgBTPcJ1h6518Lrj3ywJA9wmd/jN0gDBIBgNVHSAEQTA/
// MD0GCGCBHIbvKgEBMDEwLwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cuY2ZjYS5jb20u
// Y24vdXMvdXMtMTQuaHRtMDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly91Y3JsLmNm
// Y2EuY29tLmNuL1JTQS9jcmw0NDkxLmNybDALBgNVHQ8EBAMCA+gwHQYDVR0OBBYE
// FAFmIOdt15XLqqz13uPbGQwtj4PAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqG
// SIb3DQEBBQUAA4IBAQB8YuMQWDH/Ze+e+2pr/914cBt94FQpYqZOmrBIQ8kq7vVm
// TTy94q9UL0pMMHDuFJV6Wxng4Me/cfVvWmjgLg/t7bdz0n6UNj4StJP17pkg68WG
// zMlcjuI7/baxtDrD+O8dKpHoHezqhx7dfh1QWq8jnqd3DFzfkhEpuIt6QEaUqoWn
// t5FxSUiykTfjnaNEEGcn3/n2LpwrQ+upes12/B778MQETOsVv4WX8oE1Qsv1XLRW
// i0DQetTU2RXTrynv+l4kMy0h9b/Hdlbuh2s0QZqlUMXx2biy0GvpF2pR8f+OaLuT
// AtaKdU4T2+jO44+vWNNN2VoAaw0xY6IZ3/A1GL0x
// -----END CERTIFICATE-----
// `

// 	InitUnionKey(conf)

// 	// req := UnionConsumeRequest{}
// 	// req.OrderId = "testorderid"
// 	// req.BackUrl = "http://www.cegou.co/payment/union"
// 	// req.TxnAmt = "1"
// 	// log.Println(req.Post())

// 	req := UnionQueryOrderRequest{}
// 	req.OrderId = "testorderid"
// 	req.TxnTime = "20160618143731"
// 	log.Println(req.Post())
// }
