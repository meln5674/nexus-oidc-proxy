package proxy

import (
	"encoding/json"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	DefaultAddress = "127.0.0.1:8088"
)

type URL struct {
	Inner url.URL
}

func (u *URL) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	log.Debug(s)
	maybeURL, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.Inner = *maybeURL
	return nil
}

type Duration struct {
	Inner time.Duration
}

func (d *Duration) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	log.Debug(s)
	d.Inner, err = time.ParseDuration(s)
	if err != nil {
		return err
	}
	return nil
}

type ProxyOIDCConfig struct {
	AccessTokenHeader string   `json:"accessTokenHeader"`
	SyncInterval      Duration `json:"syncInterval"`
	RoleTemplates     []string `json:"roleTemplates"`
	DefaultRoles      []string `json:"defaultRoles"`
	UserTemplate      string   `json:"userTemplate"`
	WellKnownURL      URL      `json:"wellKnownURL"`
}
type ProxyNexusConfig struct {
	Upstream      URL    `json:"upstream"`
	RUTAuthHeader string `json:"rutAuthHeader"`
}

type ProxyHTTPConfig struct {
	Address       string                    `json:"address"`
	TokenEndpoint *ProxyTokenEndpointConfig `json:"tokenEndpoint"`
}

type ProxyTokenEndpointConfig struct {
	Path string `json:"path"`
}

type ProxyTLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type ProxyConfig struct {
	OIDC  ProxyOIDCConfig  `json:"oidc"`
	Nexus ProxyNexusConfig `json:"nexus"`
	HTTP  ProxyHTTPConfig  `json:"http"`
	TLS   ProxyTLSConfig   `json:"tls"`
}

type ProxyNexusCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ProxyCredentials struct {
	Nexus ProxyNexusCredentials `json:"nexus"`
}
