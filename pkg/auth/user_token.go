package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	resty "github.com/go-resty/resty/v2"
)

type UserToken struct {
	Username string
	Token    string
}

var userTokenCache = make(map[string]UserToken)

type UserTokenConfig struct {
	AuthToken string `ini:"auth_token" json:"authToken"`
	AuthUser  string `ini:"auth_user" json:"authUser"`
	AuthUrl   string `ini:"auth_url" json:"authUrl"`
}

func getDefaultUserTokenConf() UserTokenConfig {
	return UserTokenConfig{
		AuthToken: "",
		AuthUser:  "",
		AuthUrl:   "",
	}
}

type UserTokenAuthSetterVerifier struct {
	BaseConfig

	// token string

	UserTokenConfig
}

func NewUserTokenAuthSetterVerifier(baseCfg BaseConfig, cfg UserTokenConfig) *UserTokenAuthSetterVerifier {
	return &UserTokenAuthSetterVerifier{
		BaseConfig:      baseCfg,
		UserTokenConfig: cfg,
	}
}

func (auth *UserTokenAuthSetterVerifier) SetLogin(loginMsg *msg.Login) (err error) {
	loginMsg.AuthUser = auth.AuthUser
	loginMsg.AuthToken = auth.AuthToken
	return nil
}

func (auth *UserTokenAuthSetterVerifier) SetPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	pingMsg.AuthUser = auth.AuthUser
	pingMsg.AuthToken = auth.AuthToken
	return nil
}

func (auth *UserTokenAuthSetterVerifier) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}
	newWorkConnMsg.AuthUser = auth.AuthUser
	newWorkConnMsg.AuthToken = auth.AuthToken
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyLogin(loginMsg *msg.Login) error {
	if ok, err := auth.VerifyFromRemote(loginMsg.AuthUser, loginMsg.AuthToken); !ok {
		return err
	}
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	if ok, err := auth.VerifyFromRemote(pingMsg.AuthUser, pingMsg.AuthToken); !ok {
		return err
	}
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	if ok, err := auth.VerifyFromRemote(newWorkConnMsg.AuthUser, newWorkConnMsg.AuthToken); !ok {
		return err
	}
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyFromRemote(username, token string) (bool, error) {
	if val, ok := userTokenCache[username]; ok {
		return val.Token == token, nil
	} else {
		client := resty.New()
		client.SetRetryCount(3).
			SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
			SetScheme("https").
			SetBaseURL("localhost:8443").
			SetRetryWaitTime(5 * time.Second).
			SetRetryMaxWaitTime(20 * time.Second).
			SetRetryAfter(func(client *resty.Client, resp *resty.Response) (time.Duration, error) {
				return 0, errors.New("failed to get user toke, status:" + resp.Status() + ", body:" + resp.String())
			})

		commonResp := &msg.CommonResponse{
			Data: &msg.User{},
		}
		resp, err := client.R().
			SetResult(commonResp).
			SetQueryString("username=" + username).
			Get(auth.AuthUrl)

		if err == nil && resp.RawResponse.StatusCode == 200 && commonResp.Code == 0 {
			userTokenCache[username] = UserToken{
				Username: commonResp.Data.(*msg.User).Username,
				Token:    commonResp.Data.(*msg.User).Token,
			}
			return true, nil
		} else {
			return false, fmt.Errorf("token in NewWorkConn doesn't match token from configuration")
		}
	}
}
