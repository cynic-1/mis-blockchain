package Node

import (
	com "MIS-BC/common"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type WeChat struct {
	AppId       string `json:"app_id"`
	AppSecret   string `json:"app_secret"`
	AccessToken string `json:"access_token"`
}

type SnsOauth2 struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	Openid       string `json:"openid"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`
}

type WXUserInfo struct {
	AccessToken string                   `json:"access_token"`
	NickName    string                   `json:"nickname"`
	Sex         int                      `json:"sex"`
	Province    string                   `json:"province"`
	City        string                   `json:"city"`
	Country     string                   `json:"country"`
	HeadimgURL  string                   `json:"headimgurl"`
	Privilege   []map[string]interface{} `json:"privilege"`
	Unionid     string                   `json:"unionid"`
}

type AccessTokenErrorResponse struct {
	ErrMsg  string `json:"errmsg"`
	ErrCode string `json:"errcode"`
}

func (weChat *WeChat) SetConfig(config com.Config) {
	weChat.AppId = config.AppId
	weChat.AppSecret = config.AppSecret
}

//授权
func (weChat *WeChat) GetAuthUrl(redirectUrl string) string {
	oauth2Url := fmt.Sprintf(
		"https://open.weixin.qq.com/connect/oauth2/authorize?appid="+
			"%s&redirect_uri=%s&response_type=code&scope=snsapi_userinfo&state=STATE#wechat_redirect",
		weChat.AppId, redirectUrl)
	return oauth2Url
}

//通过code换取网页授权access_token,再通过access_token获取用户信息
func (weChat *WeChat) GetWxOpenIdFromOauth2(code string) (*WXUserInfo, error) {
	atr := SnsOauth2{}
	requestLine_access_token := strings.Join([]string{
		"https://api.weixin.qq.com/sns/oauth2/access_token",
		"?appid=", weChat.AppId,
		"&secret=", weChat.AppSecret,
		"&code=", code,
		"&grant_type=authorization_code"}, "")

	resp1, err := http.Get(requestLine_access_token)
	if err != nil || resp1.StatusCode != http.StatusOK {
		com.Logger.Error("发送get请求获取 openid 错误", err)
		return nil, err
	}
	defer resp1.Body.Close()
	body1, err := ioutil.ReadAll(resp1.Body)
	if err != nil {
		com.Logger.Error("发送get请求获取 openid 读取返回body错误", err)
		return nil, err
	}
	if bytes.Contains(body1, []byte("errcode")) {
		ater := AccessTokenErrorResponse{}
		err = json.Unmarshal(body1, &ater)
		if err != nil {
			com.Logger.Error("发送get请求获取 openid 的错误信息 %+v\n", ater)
			return nil, err
		}
	} else {
		err = json.Unmarshal(body1, &atr)
		if err != nil {
			com.Logger.Error("发送get请求获取 openid 返回数据json解析错误", err)
			return nil, err
		}
	}
	requestLine_userinfo := strings.Join([]string{
		"https://api.weixin.qq.com/sns/userinfo",
		"?access_token=", atr.AccessToken,
		"&openid=", atr.Openid}, "")
	resp2, err := http.Get(requestLine_userinfo)
	if err != nil || resp2.StatusCode != http.StatusOK {
		com.Logger.Error("发送get请求获取 userinfo 错误", err)
		return nil, err
	}
	defer resp2.Body.Close()
	body2, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		com.Logger.Error("发送get请求获取 userinfo 读取返回body错误", err)
		return nil, err
	}
	if bytes.Contains(body2, []byte("errcode")) {
		ater := AccessTokenErrorResponse{}
		err = json.Unmarshal(body2, &ater)
		if err != nil {
			com.Logger.Error("发送get请求获取 userinfo 的错误信息 %+v\n", ater)
			return nil, err
		}
	} else {
		wxuinfo := WXUserInfo{}
		err = json.Unmarshal(body2, &wxuinfo)
		if err != nil {
			com.Logger.Error("发送get请求获取 userinfo 返回数据json解析错误", err)
			return nil, err
		}
		return &wxuinfo, nil
	}
	return nil, nil
}

// 刷新或续期access_token使用
//接口说明
//access_token是调用授权关系接口的调用凭证，由于access_token有效期（目前为2个小时）较短，当access_token超时后，
//可以使用refresh_token进行刷新，access_token刷新结果有两种：
//1. 若access_token已超时，那么进行refresh_token会获取一个新的access_token，新的超时时间；
//2. 若access_token未超时，那么进行refresh_token不会改变access_token，但超时时间会刷新，相当于续期access_token。
//refresh_token拥有较长的有效期（30天），当refresh_token失效的后，需要用户重新授权，所以，请开发者在refresh_token即将过期时（如第29天时） ，
//进行定时的自动刷新并保存好它。
func (weChat *WeChat) RefreshToken(refreshtoken string) (*SnsOauth2, error) {
	atr := SnsOauth2{}
	requestLine_refreshtoken := strings.Join([]string{
		"https://api.weixin.qq.com/sns/oauth2/refresh_token",
		"?appid=", weChat.AppId,
		"&grant_type=refresh_token",
		"&refresh_token=", refreshtoken}, "")

	resp, err := http.Get(requestLine_refreshtoken)
	if err != nil || resp.StatusCode != http.StatusOK {
		com.Logger.Error("发送get请求获取 refreahtoken 错误", err)
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		com.Logger.Error("发送get请求获取 refreahtoken 读取返回body错误", err)
		return nil, err
	}
	if bytes.Contains(body, []byte("errcode")) {
		ater := AccessTokenErrorResponse{}
		err = json.Unmarshal(body, &ater)
		if err != nil {
			com.Logger.Error("发送get请求获取 refreahtoken 的错误信息 %+v\n", ater)

			return nil, err
		}
		return nil, fmt.Errorf("%s", ater.ErrMsg)
	} else {
		err = json.Unmarshal(body, &atr)
		if err != nil {
			com.Logger.Error("发送get请求获取 refreahtoken 返回数据json解析错误", err)
			return nil, err
		}
		return &atr, nil
	}
}

// 检验授权凭证（access_token）是否有效
func (weChat *WeChat) CheckAccessToken(accesstoken, openid string) (bool, error) {
	atr := AccessTokenErrorResponse{}
	requestLine_checktoken := strings.Join([]string{
		"https://api.weixin.qq.com/sns/auth?/access_token=", accesstoken,
		"&openid=", openid}, "")

	resp, err := http.Get(requestLine_checktoken)
	if err != nil || resp.StatusCode != http.StatusOK {
		com.Logger.Error("发送get请求检验 token 错误", err)
		return false, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		com.Logger.Error("发送get请求检验 token 读取返回body错误", err)
		return false, err
	}

	if bytes.Contains(body, []byte("errcode")) {
		ater := AccessTokenErrorResponse{}
		err = json.Unmarshal(body, &ater)
		if err != nil {
			com.Logger.Error("发送get请求检验 token 的错误信息 %+v\n", ater)
			return false, err
		} else if ater.ErrMsg != "ok" {
			return false, fmt.Errorf("%s", ater.ErrMsg)
		}

	}

	err = json.Unmarshal(body, &atr)
	if err != nil {
		com.Logger.Error("发送get请求获取 refreahtoken 返回数据json解析错误", err)
		return false, err
	}
	if atr.ErrCode != "0" {
		return false, nil
	} else {
		return true, nil
	}

}
