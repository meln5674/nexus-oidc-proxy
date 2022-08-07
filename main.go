package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"github.com/aquasecurity/yaml"
	jwt "github.com/golang-jwt/jwt/v4"
	flag "github.com/spf13/pflag"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"
)

const (
	NexusUsernameEnv = "NEXUS_OIDC_PROXY_NEXUS_USERNAME"
	NexusPasswordEnv = "NEXUS_OIDC_PROXY_NEXUS_PASSWORD"
)

var (
	ConfigPath     = flag.String("config", "./nexus-oidc-proxy.cfg", "Path to YAML/JSON formatted configuration file")
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
	fmt.Println(s)
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
	fmt.Println(s)
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
	UserTemplate      string   `json:"userTemplate"`
	WellKnownURL      URL      `json:"wellKnownURL"`
}
type ProxyNexusConfig struct {
	Upstream      URL    `json:"upstream"`
	RUTAuthHeader string `json:"rutAuthHeader"`
}

type ProxyHTTPConfig struct {
	Address string `json:"address"`
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

type ProxyState struct {
	Config       *ProxyConfig
	Credentials  *ProxyCredentials
	LastUserSync map[string]time.Time
	ReverseProxy httputil.ReverseProxy
}

func NewProxy(config ProxyConfig, credentials ProxyCredentials) (*ProxyState, error) {
	state := &ProxyState{
		Config:       &config,
		Credentials:  &credentials,
		LastUserSync: make(map[string]time.Time),
	}
	state.ReverseProxy.Director = state.Director
	state.ReverseProxy.ModifyResponse = state.ModifyResponse
	state.ReverseProxy.ErrorLog = log.Default()
	return state, nil
}

type RolesContext struct {
	Token *jwt.Token
}

type NexusUser struct {
	UserID       string   `json:"userId"`
	FirstName    string   `json:"firstName"`
	LastName     string   `json:"lastName"`
	EmailAddress string   `json:"emailAddress"`
	Password     string   `json:"password"`
	Status       string   `json:"status"`
	Roles        []string `json:"roles"`
}

type NexusUserUpdate struct {
	NexusUser     `json:",inline"`
	Source        string   `json:"source"`
	ReadOnly      bool     `json:"readOnly"`
	ExternalRoles []string `json:"externalRoles"`
}

func (p *ProxyState) GetOnboardedUser(token *jwt.Token) (*NexusUser, error) {
	// TODO: pre-compile templates
	tpl, err := template.New("rbac.userTemplate").Funcs(sprig.TxtFuncMap()).Parse(p.Config.OIDC.UserTemplate)
	if err != nil {
		return nil, err
	}
	output := strings.Builder{}
	err = tpl.Execute(&output, RolesContext{Token: token})
	if err != nil {
		return nil, err
	}
	log.Printf("User template output: %s\n", output.String())
	user := NexusUser{}
	err = yaml.Unmarshal([]byte(output.String()), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *ProxyState) GetDesiredUserRoles(token *jwt.Token) ([]string, error) {
	roleSet := make(map[string]struct{})
	for ix, tplStr := range p.Config.OIDC.RoleTemplates {
		tpl, err := template.New(fmt.Sprintf("rbac.roleTemplates[%d]", ix)).Funcs(sprig.TxtFuncMap()).Parse(tplStr)
		if err != nil {
			return nil, err
		}
		output := strings.Builder{}
		err = tpl.Execute(&output, RolesContext{Token: token})
		if err != nil {
			return nil, err
		}
		templateRoles := make([]string, 0)
		err = yaml.Unmarshal([]byte(output.String()), &templateRoles)
		if err != nil {
			return nil, err
		}

		for _, role := range templateRoles {
			roleSet[role] = struct{}{}
		}
	}

	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}

	return roles, nil
}

func (p *ProxyState) GetUser(userID string) (*NexusUser, bool, error) {
	getUser := p.Config.Nexus.Upstream.Inner
	getUser.Path += "service/rest/v1/security/users"
	getUser.RawQuery = fmt.Sprintf("userId=%s&source=default", userID)
	req, err := http.NewRequest(http.MethodGet, getUser.String(), nil)
	if err != nil {
		return nil, false, err
	}
	req.SetBasicAuth(p.Credentials.Nexus.Username, p.Credentials.Nexus.Password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return nil, false, fmt.Errorf("GET %s: %s - %s", &getUser, res.Status, string(body))
	}
	result := make([]NexusUser, 0, 1)
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return nil, false, err
	}
	if len(result) == 0 {
		return nil, false, nil
	}
	user := result[0]
	return &user, true, nil
}

func (p *ProxyState) CreateUser(user *NexusUser) error {
	postUser := p.Config.Nexus.Upstream.Inner
	postUser.Path += "service/rest/v1/security/users"
	userBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, postUser.String(), ioutil.NopCloser(bytes.NewReader(userBytes)))
	if err != nil {
		return err
	}
	req.SetBasicAuth(p.Credentials.Nexus.Username, p.Credentials.Nexus.Password)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("POST %s: %s - %s", &postUser, res.Status, string(body))
	}
	return nil
}

func (p *ProxyState) UpdateUser(user *NexusUser) error {
	putUser := p.Config.Nexus.Upstream.Inner
	putUser.Path += fmt.Sprintf("service/rest/v1/security/users/%s", user.UserID)
	userUpdate := NexusUserUpdate{
		NexusUser:     *user,
		Source:        "default",
		ReadOnly:      false,
		ExternalRoles: make([]string, 0),
	}
	userBytes, err := json.Marshal(&userUpdate)
	if err != nil {
		return err
	}
	fmt.Println(userUpdate)
	fmt.Println(string(userBytes))
	req, err := http.NewRequest(http.MethodPut, putUser.String(), ioutil.NopCloser(bytes.NewReader(userBytes)))
	if err != nil {
		return err
	}
	req.SetBasicAuth(p.Credentials.Nexus.Username, p.Credentials.Nexus.Password)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("PUT %s: %s - %s", &putUser, res.Status, string(body))
	}
	return nil
}

func (p *ProxyState) Director(r *http.Request) {
	incomingURL := *r.URL
	*r.URL = p.Config.Nexus.Upstream.Inner
	r.URL.Path += incomingURL.Path
	defer log.Println(r)

	rawToken, ok := r.Header[p.Config.OIDC.AccessTokenHeader]
	if !ok || len(rawToken) == 0 {
		log.Printf("No access token present (%s)", p.Config.OIDC.AccessTokenHeader)
		return
	}
	//token, err := jwt.NewParser().Parse(rawToken[0], func(token *jwt.Token) (interface{}, error) { return token, nil })
	claims := make(jwt.MapClaims)
	// TODO: Deal with signature
	token, _, err := jwt.NewParser().ParseUnverified(rawToken[0], claims)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Got token %#v\n", token)
	onboardedUser, err := p.GetOnboardedUser(token)
	if err != nil {
		log.Println(err)
		return
	}
	if onboardedUser.UserID == "" {
		log.Printf("UserID cannot be empty, skipping rbac check: %#v\n", onboardedUser)
		return
	}
	existingUser, found, err := p.GetUser(onboardedUser.UserID)
	if err != nil {
		log.Println(err)
		return
	}
	if !found {
		err = p.CreateUser(onboardedUser)
		if err != nil {
			log.Println(err)
			return
		}
		existingUser, found, err = p.GetUser(onboardedUser.UserID)
		if err != nil {
			log.Println(err)
			return
		}
		if !found {
			log.Printf("User %s did not exist after creation?\n", onboardedUser.UserID)
			return
		}
	}
	r.Header.Add(p.Config.Nexus.RUTAuthHeader, existingUser.UserID)
	lastSync := p.LastUserSync[existingUser.UserID]
	if time.Now().Before(lastSync.Add(p.Config.OIDC.SyncInterval.Inner)) {
		return
	}
	fmt.Println("Sync period has expired, syncing roles")
	roles, err := p.GetDesiredUserRoles(token)
	if err != nil {
		log.Println(err)
		return
	}
	existingUser.Roles = roles
	fmt.Printf("New User: %#v\n", existingUser)
	err = p.UpdateUser(existingUser)
	if err != nil {
		log.Println(err)
		return
	}
	p.LastUserSync[existingUser.UserID] = time.Now()
}

func (p *ProxyState) ModifyResponse(resp *http.Response) error {
	log.Println(resp)
	return nil
}

func (p *ProxyState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.ReverseProxy.ServeHTTP(w, r)
}

func (p *ProxyState) ListenAndServe() error {
	server := http.Server{
		Addr:    p.Config.HTTP.Address,
		Handler: p,
	}
	if p.Config.TLS.Enabled {
		return server.ListenAndServeTLS(p.Config.TLS.CertFile, p.Config.TLS.KeyFile)
	}
	return server.ListenAndServe()
}

// TODO: Add an optional endpoint which, if called with a valid token, will set the password based on a template given the token and the query claims
// This will allow users to set their internal nexus password, which should not be needed when accessing through the proxy, but if accessed through a second endpoint which bypasses the proxy, will act as a "token", rather than an SSO password, for example, in a maven settings.xml

func main() {
	flag.Parse()

	configFile, err := os.Open(*ConfigPath)
	if err != nil {
		log.Fatal(err)
	}

	configBytes, err := ioutil.ReadAll(configFile)
	if err != nil {
		log.Fatal(err)
	}

	config := ProxyConfig{}

	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatal(err)
	}

	credentials := ProxyCredentials{
		Nexus: ProxyNexusCredentials{
			Username: os.Getenv(NexusUsernameEnv),
			Password: os.Getenv(NexusPasswordEnv),
		},
	}

	proxy, err := NewProxy(config, credentials)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Listening on %s\n", proxy.Config.HTTP.Address)
	fmt.Printf("Proxying %s\n", proxy.Config.Nexus.Upstream.Inner.String())
	log.Fatal(proxy.ListenAndServe())
}
