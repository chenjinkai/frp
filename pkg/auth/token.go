// Copyright 2020 guylewin, guy@lewin.co.il
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"fmt"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

type TokenConfig struct {
	// Token specifies the authorization token used to create keys to be sent
	// to the server. The server must have a matching token for authorization
	// to succeed.  By default, this value is "".
	Token    string `ini:"token" json:"token"`
	AuthUser string `ini:"auth_user" json:"authuser"`
}

func getDefaultTokenConf() TokenConfig {
	return TokenConfig{
		Token:    "",
		AuthUser: "",
	}
}

type TokenAuthSetterVerifier struct {
	BaseConfig

	// token string

	TokenConfig
}

func NewTokenAuth(baseCfg BaseConfig, cfg TokenConfig) *TokenAuthSetterVerifier {
	return &TokenAuthSetterVerifier{
		BaseConfig: baseCfg,
		// token:      cfg.Token,
		TokenConfig: cfg,
	}
}

func (auth *TokenAuthSetterVerifier) SetLogin(loginMsg *msg.Login) (err error) {
	loginMsg.PrivilegeKey = util.GetAuthKey(auth.TokenConfig.Token, loginMsg.Timestamp)
	loginMsg.Token = auth.TokenConfig.Token
	loginMsg.AuthUser = auth.TokenConfig.AuthUser
	return nil
}

func (auth *TokenAuthSetterVerifier) SetPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	pingMsg.Timestamp = time.Now().Unix()
	pingMsg.PrivilegeKey = util.GetAuthKey(auth.TokenConfig.Token, pingMsg.Timestamp)
	pingMsg.Token = auth.TokenConfig.Token
	pingMsg.AuthUser = auth.TokenConfig.AuthUser
	return nil
}

func (auth *TokenAuthSetterVerifier) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	newWorkConnMsg.Timestamp = time.Now().Unix()
	newWorkConnMsg.PrivilegeKey = util.GetAuthKey(auth.TokenConfig.Token, newWorkConnMsg.Timestamp)
	newWorkConnMsg.Token = auth.TokenConfig.Token
	newWorkConnMsg.AuthUser = auth.TokenConfig.AuthUser
	return nil
}

func (auth *TokenAuthSetterVerifier) VerifyLogin(loginMsg *msg.Login) error {
	if util.GetAuthKey(auth.TokenConfig.Token, loginMsg.Timestamp) != loginMsg.PrivilegeKey {
		return fmt.Errorf("token in login doesn't match token from configuration")
	}
	return nil
}

func (auth *TokenAuthSetterVerifier) VerifyPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	if util.GetAuthKey(auth.TokenConfig.Token, pingMsg.Timestamp) != pingMsg.PrivilegeKey {
		return fmt.Errorf("token in heartbeat doesn't match token from configuration")
	}
	return nil
}

func (auth *TokenAuthSetterVerifier) VerifyNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	if util.GetAuthKey(auth.TokenConfig.Token, newWorkConnMsg.Timestamp) != newWorkConnMsg.PrivilegeKey {
		return fmt.Errorf("token in NewWorkConn doesn't match token from configuration")
	}
	return nil
}
