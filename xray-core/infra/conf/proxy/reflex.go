package proxy

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexInboundConfig struct {
	// به جای استفاده از conf.User، مستقیماً ساختار را تعریف می‌کنیم تا Cycle ایجاد نشود
	Users []struct {
		Email string `json:"email"`
	} `json:"clients"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{}
	for _, rawUser := range c.Users {
		user := &reflex.User{
			Id: rawUser.Email,
		}
		config.Clients = append(config.Clients, user)
	}
	return config, nil
}
