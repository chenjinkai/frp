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

type UserTokenConfig struct {
	AuthToken string `ini:"auth_token" json:"authToken"`
	AuthUser  string `ini:"auth_user" json:"authUser"`
	AuthUrl   string `ini:"auth_url" json:"authUrl"`
}

func getDefaultUserTokenConf() UserTokenConfig {
	return UserTokenConfig{
		AuthToken: "",
		AuthUser:  "",
		AuthUrl:   "/clients/verify",
	}
}

type UserTokenAuthSetterVerifier struct {
	BaseConfig

	// token string
	UserTokenConfig

	FrpAdminHost string
}

func NewUserTokenAuthSetterVerifier(frpAdminHost string, baseCfg BaseConfig, cfg UserTokenConfig) *UserTokenAuthSetterVerifier {
	return &UserTokenAuthSetterVerifier{
		BaseConfig:      baseCfg,
		UserTokenConfig: cfg,
		FrpAdminHost:    frpAdminHost,
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
	if ok, err := auth.VerifyFromRemote(auth.FrpAdminHost, loginMsg.AuthUser, loginMsg.AuthToken); !ok {
		return err
	}
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	if ok, err := auth.VerifyFromRemote(auth.FrpAdminHost, pingMsg.AuthUser, pingMsg.AuthToken); !ok {
		return err
	}
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	if ok, err := auth.VerifyFromRemote(auth.FrpAdminHost, newWorkConnMsg.AuthUser, newWorkConnMsg.AuthToken); !ok {
		return err
	}
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyFromRemote(frpadminHost, username, token string) (bool, error) {
	client := resty.New()
	client.SetRetryCount(3).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		// SetScheme("https").
		SetBaseURL(frpadminHost).
		SetRetryWaitTime(5 * time.Second).
		SetRetryMaxWaitTime(20 * time.Second).
		SetRetryAfter(func(client *resty.Client, resp *resty.Response) (time.Duration, error) {
			return 0, errors.New("failed to get user toke, status:" + resp.Status() + ", body:" + resp.String())
		})

	commonResp := &msg.CommonResponse{}
	resp, err := client.R().
		SetResult(commonResp).
		SetQueryString("username=" + username + "&token=" + token).
		Get(auth.AuthUrl)

	if err == nil && resp.RawResponse.StatusCode == 200 && commonResp.Code == 0 {
		return true, nil
	} else {
		return false, fmt.Errorf("user token in NewWorkConn doesn't match user token from configuration")
	}
}
