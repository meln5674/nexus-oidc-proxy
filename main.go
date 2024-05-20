package main

import (
	"io/ioutil"
	"os"

	flag "github.com/spf13/pflag"
	"github.com/thediveo/enumflag/v2"

	log "github.com/sirupsen/logrus"

	"github.com/aquasecurity/yaml"

	"github.com/meln5674/nexus-oidc-proxy/pkg/proxy"
)

var LoglevelIds = map[log.Level][]string{
	log.TraceLevel: {"trace"},
	log.DebugLevel: {"debug"},
	log.InfoLevel:  {"info"},
	log.WarnLevel:  {"warning", "warn"},
	log.ErrorLevel: {"error"},
	log.FatalLevel: {"fatal"},
	log.PanicLevel: {"panic"},
}

const (
	NexusUsernameEnv = "NEXUS_OIDC_PROXY_NEXUS_USERNAME"
	NexusPasswordEnv = "NEXUS_OIDC_PROXY_NEXUS_PASSWORD"
)

var (
	ConfigPath          = flag.String("config", "./nexus-oidc-proxy.cfg", "Path to YAML/JSON formatted configuration file")
	LogLevel            = log.InfoLevel
	DefaultDefaultRoles = []string{"nx-anonymous"}
)

func main() {
	flag.Var(
		enumflag.New(&LogLevel, "log-level", LoglevelIds, enumflag.EnumCaseInsensitive),
		"log-level",
		"sets logging level; can be 'trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic'")

	flag.Parse()

	log.SetLevel(LogLevel)

	configFile, err := os.Open(*ConfigPath)
	if err != nil {
		log.Fatal(err)
	}

	configBytes, err := ioutil.ReadAll(configFile)
	if err != nil {
		log.Fatal(err)
	}

	config := proxy.ProxyConfig{}

	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatal(err)
	}

	credentials := proxy.ProxyCredentials{
		Nexus: proxy.ProxyNexusCredentials{
			Username: os.Getenv(NexusUsernameEnv),
			Password: os.Getenv(NexusPasswordEnv),
		},
	}

	if len(config.OIDC.DefaultRoles) == 0 {
		copy(config.OIDC.DefaultRoles, DefaultDefaultRoles)
	}

	if config.Nexus.RUTAuthHeader == "" {
		log.Fatal("Must set nexus.ruthAuthHeader")
	}

	if config.OIDC.AccessTokenHeader == "" {
		log.Fatal("Must set oidc.accessTokenHeader")
	}

	srv, err := proxy.NewProxy(config, credentials)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Listening on %s", srv.Config.HTTP.Address)
	log.Infof("Proxying %s", srv.Config.Nexus.Upstream.Inner.String())
	log.Fatal(srv.ListenAndServe())
}
