package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/meln5674/gotoken"
	log "github.com/sirupsen/logrus"

	"github.com/Masterminds/sprig/v3"

	"github.com/aquasecurity/yaml"

	"github.com/golang-jwt/jwt/v4"
)

type ProxyState struct {
	Config      *ProxyConfig
	GetToken    gotoken.TokenGetter
	Credentials *ProxyCredentials
	UsersCache  sync.Map
	httputil.ReverseProxy
	*http.ServeMux
}

type UserCacheEntry struct {
	User          *NexusUser
	LastSync      time.Time
	RolesLastSync time.Time
}

func NewProxy(config ProxyConfig, credentials ProxyCredentials) (*ProxyState, error) {
	state := &ProxyState{
		Config:      &config,
		Credentials: &credentials,
	}

	var ok bool
	state.GetToken, ok = gotoken.GetTokenGetter(
		config.OIDC.TokenMode,
		&gotoken.TokenGetterArgs{
			HeaderName: config.OIDC.AccessTokenHeader,
			Parser:     jwt.NewParser(),
			// TODO: Deal with signature
			InsecureSkipVerification: true,
		},
	)
	if !ok {
		return nil, fmt.Errorf("Invalid tokenMode: %s", config.OIDC.TokenMode)
	}

	users, err := state.GetUsers(nil)
	if err != nil {
		log.Printf("Error while warming up users cache: %s. Starting with empty cache", err)
	} else {
		for _, user := range users {
			state.UsersCache.Store(user.UserID, UserCacheEntry{
				User:     &user,
				LastSync: time.Now(),
			})
		}
		log.Printf("Saved %d users in local cache\n", len(users))
	}

	w := log.New().Writer()
	defer w.Close()

	state.ReverseProxy.Director = state.Director
	state.ReverseProxy.ModifyResponse = state.ModifyResponse
	state.ReverseProxy.ErrorLog = stdlog.New(w, "", 0)
	state.ServeMux = http.NewServeMux()
	if config.HTTP.TokenEndpoint != nil {
		if config.HTTP.TokenEndpoint.Path == "" {
			return nil, fmt.Errorf("Invalid token endpoint path: %s", config.HTTP.TokenEndpoint.Path)
		}
		state.ServeMux.HandleFunc(config.HTTP.TokenEndpoint.Path, state.TokenEndpoint)
	}
	state.ServeMux.Handle("/", &state.ReverseProxy)
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
	log.Debugf("User template output: %s\n", output.String())
	user := NexusUser{}
	err = yaml.Unmarshal([]byte(output.String()), &user)
	if err != nil {
		return nil, err
	}
	if user.UserID == "" {
		return nil, fmt.Errorf("UserID cannot be empty: %#v", user)
	}
	if len(user.Roles) == 0 {
		copy(user.Roles, p.Config.OIDC.DefaultRoles)
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
	if len(roles) == 0 {
		copy(roles, p.Config.OIDC.DefaultRoles)
	}

	return roles, nil
}

func (p *ProxyState) GetUsers(userID *string) ([]NexusUser, error) {
	getUser := p.Config.Nexus.Upstream.Inner
	getUser.Path += "service/rest/v1/security/users"
	if userID != nil {
		getUser.RawQuery = fmt.Sprintf("userId=%s&source=default", *userID)
	} else {
		getUser.RawQuery = "source=default"
	}
	req, err := http.NewRequest(http.MethodGet, getUser.String(), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.Credentials.Nexus.Username, p.Credentials.Nexus.Password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return nil, fmt.Errorf("GET %s: %s - %s", &getUser, res.Status, string(body))
	}
	tmpResult := make([]NexusUser, 0, 1)
	err = json.NewDecoder(res.Body).Decode(&tmpResult)
	if err != nil {
		return nil, err
	}
	// Nexus API filters results by prefix instead of exact match
	// This ensures that the user returned is the user requested by userID variable
	result := make([]NexusUser, 0, 1)
	if userID != nil {
		for _, user := range tmpResult {
			if user.UserID == *userID {
				result = append(result, user)
			}
		}
	} else {
		result = tmpResult
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func (p *ProxyState) GetUser(userID string) (*NexusUser, bool, error) {
	result, err := p.GetUsers(&userID)
	if err != nil {
		return nil, false, err
	}
	if len(result) == 0 {
		return nil, false, nil
	}
	return &result[0], true, nil
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
	// 200 <= result < 300
	if res.StatusCode < 200 || res.StatusCode >= 300 {
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
	log.Debug(userUpdate)
	log.Debug(string(userBytes))
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
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("PUT %s: %s - %s", &putUser, res.Status, string(body))
	}
	return nil
}

func (p *ProxyState) ChangePassword(userID, password string) error {
	changePasswordURL := p.Config.Nexus.Upstream.Inner
	changePasswordURL.Path = fmt.Sprintf("%s/service/rest/v1/security/users/%s/change-password", changePasswordURL.Path, userID)
	req, err := http.NewRequest(http.MethodPut, changePasswordURL.String(), strings.NewReader(password))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	req.SetBasicAuth(p.Credentials.Nexus.Username, p.Credentials.Nexus.Password)
	resp, err := http.DefaultClient.Do(req) // TODO: Will we ever need to use a different client?
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			body = []byte(fmt.Sprintf("<Failed to read response body: %s>", err))
		}
		if len(body) == 0 {
			body = []byte("<No body>")
		}
		return fmt.Errorf("%s: %s", resp.Status, string(body))
	}
	return nil
}

func (p *ProxyState) ExtractClaims(r *http.Request) (token *jwt.Token, err error) {
	token, ok, err := p.GetToken(r)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("No access token present (%s)", p.Config.OIDC.AccessTokenHeader)
	}
	return token, nil
}

func (p *ProxyState) Director(r *http.Request) {
	incomingURL := *r.URL
	r.URL.Host = p.Config.Nexus.Upstream.Inner.Host
	r.URL.Scheme = p.Config.Nexus.Upstream.Inner.Scheme
	r.URL.Path = p.Config.Nexus.Upstream.Inner.Path + incomingURL.Path
	defer log.Debug(r)
	token, err := p.ExtractClaims(r)
	if err != nil {
		log.Errorf("Failed to extract claims: %s", err)
		return
	}
	log.Debugf("Got token %#v\n", token)
	onboardedUser, err := p.GetOnboardedUser(token)
	if err != nil {
		log.Error(err)
		return
	}
	var existingUser *NexusUser
	var found bool
	var cachedUser UserCacheEntry
	cachedValue, exists := p.UsersCache.Load(onboardedUser.UserID)
	if exists {
		cachedUser = cachedValue.(UserCacheEntry)
	}
	// If user in cache and recently updated, use cached user
	if exists && time.Now().Before(cachedUser.LastSync.Add(p.Config.OIDC.SyncInterval.Inner)) {
		existingUser = cachedUser.User
		found = true
		log.Infof("Found user %s in local cache and in-sync\n", existingUser.UserID)
		// Else retrieve user from nexus server
	} else {
		existingUser, found, err = p.GetUser(onboardedUser.UserID)
		if err != nil {
			log.Errorf("Error while fetching user from Nexus: %s", err)
			return
		}
		if found {
			cachedUser.LastSync = time.Now()
		}
	}
	if !found {
		// If user doesn't exist ensure we are not caching invalid data
		p.UsersCache.Delete(onboardedUser.UserID)
		err = p.CreateUser(onboardedUser)
		if err != nil {
			log.Error(err)
			return
		}
		existingUser, found, err = p.GetUser(onboardedUser.UserID)
		if err != nil {
			log.Error(err)
			return
		}
		if !found {
			log.Warnf("User %s did not exist after creation?\n", onboardedUser.UserID)
			return
		}
		cachedUser.LastSync = time.Now()
	}
	// Update user information in case user is just created or refreshed from nexus server
	cachedUser.User = existingUser
	p.UsersCache.Store(onboardedUser.UserID, cachedUser)

	r.Header.Add(p.Config.Nexus.RUTAuthHeader, existingUser.UserID)
	lastSync := cachedUser.RolesLastSync
	log.Debugf("User roles %s last synced at %v", existingUser.UserID, lastSync)
	if time.Now().Before(lastSync.Add(p.Config.OIDC.SyncInterval.Inner)) {
		return
	}
	log.Info("Sync period has expired, syncing roles")
	roles, err := p.GetDesiredUserRoles(token)
	if err != nil {
		log.Error(err)
		return
	}
	existingUser.Roles = roles
	log.Debugf("New User: %#v\n", existingUser)
	err = p.UpdateUser(existingUser)
	if err != nil {
		log.Error(err)
		return
	}
	cachedUser.RolesLastSync = time.Now()
	p.UsersCache.Store(existingUser.UserID, cachedUser)

	if p.Config.OIDC.StripHeader {
		r.Header.Del(p.Config.OIDC.AccessTokenHeader)
	}
}

func (p *ProxyState) ModifyResponse(resp *http.Response) error {
	log.Debug(resp)
	return nil
}

func (p *ProxyState) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	claims, err := p.ExtractClaims(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	onboardedUser, err := p.GetOnboardedUser(claims)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("An error occured while generating your token. Contact an administrator"))
		return
	}

	if onboardedUser.UserID == "" {
		log.Warnf("UserID cannot be empty, not setting a token: %#v\n", onboardedUser)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("You don't appear to be logged in or a valid user. Contact an Administrator"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Write([]byte(fmt.Sprintf(TokenPageStartFmt, onboardedUser.UserID, p.Config.HTTP.TokenEndpoint.Path)))
	case http.MethodPost:
		randBytes := make([]byte, 1024) // TODO: Will we every need more entropy than this?
		_, err := rand.Read(randBytes)
		if err != nil { // This technically should never happen, but better safe than sorry
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("An error occured while generating your token. Contact an administrator"))
			return
		}

		hash := sha256.New()
		hash.Write(randBytes)
		digest := hash.Sum(make([]byte, 0))
		newPassword := base64.StdEncoding.EncodeToString(digest)

		err = p.ChangePassword(onboardedUser.UserID, newPassword)
		if err != nil {
			log.Errorf("Failed to set user password: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf(TokenPageFailureFmt, onboardedUser.UserID, p.Config.HTTP.TokenEndpoint.Path)))
			return
		}
		w.Write([]byte(fmt.Sprintf(TokenPageSuccessFmt, onboardedUser.UserID, p.Config.HTTP.TokenEndpoint.Path, newPassword)))
		return

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return

	}

}

func (p *ProxyState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.ServeMux.ServeHTTP(w, r)
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
