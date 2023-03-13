package auth

import (
	"fmt"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

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
	if util.GetAuthKey(auth.Token, loginMsg.Timestamp) != loginMsg.PrivilegeKey {
		return fmt.Errorf("token in login doesn't match token from configuration")
	}
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	if util.GetAuthKey(auth.Token, pingMsg.Timestamp) != pingMsg.PrivilegeKey {
		return fmt.Errorf("token in heartbeat doesn't match token from configuration")
	}
	return nil
}

func (auth *UserTokenAuthSetterVerifier) VerifyNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	if util.GetAuthKey(auth.Token, newWorkConnMsg.Timestamp) != newWorkConnMsg.PrivilegeKey {
		return fmt.Errorf("token in NewWorkConn doesn't match token from configuration")
	}
	return nil
}
