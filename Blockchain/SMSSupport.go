package Node

import (
	com "MIS-BC/common"
	"crypto/rand"
	"errors"
	"github.com/patrickmn/go-cache"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	e "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	sms "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sms/v20210111"
	"io"
	"time"
)

type SMS struct {
	Appid            string
	Signid           string
	Templateid       string
	VerificationCode *cache.Cache
	ValidPeriod      string
	Secretid         string
	Secretkey        string
}

func (m *SMS) SetConfig(config com.Config) {
	m.Secretid = config.SecretID
	m.Secretkey = config.SecretKey
	m.Signid = "MINVPN"
	m.Appid = "1400583953"
	m.Templateid = "1158268"
	m.VerificationCode = cache.New(10*time.Minute, 10*time.Second)
	m.ValidPeriod = "10"
}

//func NewSMS(appid,phone,templateid string)*SMS  {
//	return &SMS{
//		Appid: appid,
//		Phone: phone,
//		Templateid: templateid,
//	}
//}

func (m *SMS) Setsignid(signid string) {
	m.Signid = signid
}
func (m *SMS) GenerateVerificationCode() string {
	//生成六位随机数
	var table = [10]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
	b := make([]byte, 6)
	n, err := io.ReadAtLeast(rand.Reader, b, 6)
	if n != 6 {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b)
	//cache包清除验证码实现时效性
	//c := cache.New(10*time.Minute, 10*time.Second)
	//c.Set(m.VerificationCode, string(b), cache.DefaultExpiration)
	/*测试是否清除
	value, found := c.Get(m.templateparam1)
	if found {
		log.Println("found:", value)
	} else {
		log.Println("not found")
	}

	time.Sleep(5*time.Second)
	log.Println("sleep 5s...")
	value, found = c.Get("Title")
	if found {
		log.Println("found:", value)
	} else {
		log.Println("not found")
	}*/
}
func (m *SMS) SetValidPeriod(validperiod string) {
	m.ValidPeriod = validperiod
}

func (m *SMS) Setsecretid(secretid string) {
	m.Secretid = secretid
}

func (m *SMS) Setsecretkey(secretkey string) {
	m.Secretkey = secretkey
}

func (m *SMS) Sendmessage(phone string) error {
	credential := common.NewCredential(
		m.Secretid, //密钥
		m.Secretkey,
	)
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "sms.tencentcloudapi.com"
	client, _ := sms.NewClient(credential, "ap-nanjing", cpf)

	request := sms.NewSendSmsRequest()

	request.PhoneNumberSet = common.StringPtrs([]string{phone}) //下发手机号
	request.SmsSdkAppId = common.StringPtr(m.Appid)             //appid
	request.SignName = common.StringPtr(m.Signid)               //签名id
	request.TemplateId = common.StringPtr(m.Templateid)         //正文模板id
	vc, ok := m.VerificationCode.Get(phone)
	if !ok {
		com.Logger.Error("no such invalid verificationcode")
		return errors.New("no such invalid verificationcode")
	}
	vcs := vc.(*string)
	request.TemplateParamSet = common.StringPtrs([]string{*vcs, m.ValidPeriod}) //模板参数

	response, err := client.SendSms(request)
	com.Logger.Info(response.ToJsonString())
	if response != nil {
		v := *response
		if *v.Response.SendStatusSet[0].Code != "ok" && *v.Response.SendStatusSet[0].Code != "Ok" {
			return errors.New(*v.Response.SendStatusSet[0].Message)
		} else {
			return nil
		}
	}

	if err != nil {
		e, _ := err.(*e.TencentCloudSDKError)
		com.Logger.Error("An API error has returned:", (*e).Message)
		return errors.New((*e).Message)
	}

	return nil
}
