package main_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/meln5674/gingk8s"
	"github.com/meln5674/gosh"
	"github.com/onsi/biloba"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNexusOidcProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NexusOidcProxy Suite")
}

// var b *biloba.Biloba
var gk8s gingk8s.Gingk8s

var _ = BeforeSuite(func(ctx context.Context) {
	var err error

	keycloakSetupScript, err = os.ReadFile("integration-test/configure-keycloak.sh")
	Expect(err).ToNot(HaveOccurred())

	gk8s = gingk8s.ForSuite(GinkgoT())

	ingressNginxImageID := gk8s.ThirdPartyImage(ingressNginxImage)
	kubeIngressProxyImageID := gk8s.ThirdPartyImage(kubeIngressProxyImage)
	certManagerImageIDs := gk8s.ThirdPartyImages(certManagerImages...)
	nexusOIDCProxyImageID := gk8s.CustomImage(&nexusOIDCProxyImage)

	clusterID := gk8s.Cluster(&cluster, ingressNginxImageID, kubeIngressProxyImageID, certManagerImageIDs, nexusOIDCProxyImageID)

	gk8s.ClusterAction(clusterID, "Watch Pods", &watchPods)

	certManagerID := gk8s.Release(clusterID, &certManager, certManagerImageIDs)

	certsID := gk8s.Manifests(clusterID, &certs, &certManagerID)

	ingressNginxID := gk8s.Release(clusterID, &ingressNginx, ingressNginxImageID, certsID)

	gk8s.Release(clusterID, &kubeIngressProxy, ingressNginxID, kubeIngressProxyImageID)

	// The nexus chart is broken, so we have to do the install/update in two phases
	nexusID := gk8s.Release(clusterID, &nexus, ingressNginxID)
	nexusID = gk8s.Release(clusterID, &nexusAgain, nexusID)
	nexusAdminPasswordSecretID := gk8s.Manifests(clusterID, &nexusAdminPasswordSecret, nexusID)

	nexusOIDCProxyConfigID := gk8s.Manifests(clusterID, &nexusOIDCProxyConfig)
	nexusOIDCProxyID := gk8s.Release(clusterID, &nexusOIDCProxy, nexusOIDCProxyConfigID, nexusAdminPasswordSecretID)

	keycloakID := gk8s.Release(clusterID, &keycloak, ingressNginxID)
	keycloakSetupID := gk8s.ClusterAction(clusterID, "Configure Keycloak", keycloakSetup, keycloakID)

	oauth2ProxyConfigID := gk8s.Manifests(clusterID, &oauth2ProxyConfig)
	oauth2ProxyID := gk8s.Release(clusterID, &oauth2Proxy, oauth2ProxyConfigID, keycloakSetupID)

	_ = []gingk8s.ResourceDependency{
		oauth2ProxyID,
		nexusOIDCProxyID,
	}

	gk8s.Options(gingk8s.SuiteOpts{
		NoSuiteCleanup: true,
	})

	gk8s.Setup(ctx)

	clusterCA := gk8s.KubectlReturnSecretValue(ctx, &cluster, "test-cert", "tls.crt")

	clusterCertPool, err := x509.SystemCertPool()
	Expect(err).ToNot(HaveOccurred())
	clusterCertPool = clusterCertPool.Clone()
	clusterCertPool.AppendCertsFromPEM([]byte(clusterCA))

	clusterClient = &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("http://localhost:8080")
			},
			TLSClientConfig: &tls.Config{
				RootCAs: clusterCertPool,
			},
		},
	}

	Expect(gk8s.KubectlExec(ctx, &cluster, "deployment/nexus", "cat", []string{"/nexus-data/admin.password"}).WithStreams(gosh.FuncOut(gosh.SaveString(&nexusAdminPassword))).Run()).To(Succeed())

	nexusRequest(http.MethodPut, "/service/rest/v1/security/anonymous", &map[string]interface{}{"enabled": false}, nil)

	var activeRealms []string
	nexusRequest(http.MethodGet, "/service/rest/v1/security/realms/active", nil, &activeRealms)
	active := false
	for _, realm := range activeRealms {
		if realm == "rutauth-realm" {
			active = true
			break
		}
	}
	if !active {
		nexusRequest(http.MethodPut, "/service/rest/v1/security/realms/active", activeRealms, nil)
	}

	var scripts []map[string]interface{}
	scriptExists := false
	nexusRequest(http.MethodGet, "/service/rest/v1/script", nil, &scripts)
	for _, script := range scripts {
		if script["name"].(string) == "enable-rut-auth-capability" {
			scriptExists = true
			break
		}
	}

	if scriptExists {
		nexusRequest(http.MethodDelete, "/service/rest/v1/script/enable-rut-auth-capability", nil, nil)
	}

	script := map[string]interface{}{
		"name": "enable-rut-auth-capability",
		"type": "groovy",
	}
	scriptContents, err := os.ReadFile("integration-test/enable-rut-auth.groovy")
	Expect(err).ToNot(HaveOccurred())
	script["content"] = string(scriptContents)
	nexusRequest(http.MethodPost, "/service/rest/v1/script", script, nil)
	nexusRequest(http.MethodPost, "/service/rest/v1/script/enable-rut-auth-capability/run", &struct{}{}, nil)

	var repos []map[string]interface{}
	repo1Exists := false
	repo2Exists := false
	nexusRequest(http.MethodGet, "/service/rest/v1/repositories", nil, &repos)
	for _, repo := range repos {
		if repo["name"].(string) == "test-repo-1" {
			repo1Exists = true
		}
		if repo["name"].(string) == "test-repo-2" {
			repo2Exists = true
		}
		if repo1Exists && repo2Exists {
			break
		}
	}
	if !repo1Exists {
		nexusRequest(http.MethodPost, "/service/rest/v1/repositories/raw/hosted", &map[string]interface{}{
			"name":   "test-repo-1",
			"online": true,
			"storage": map[string]interface{}{
				"blobStoreName":               "default",
				"strictContentTypeValidation": true,
				"writePolicy":                 "allow_once",
			},
			"cleanup": map[string]interface{}{
				"policyNames": []string{},
			},
			"component": map[string]interface{}{
				"proprietaryComponents": true,
			},
			"raw": map[string]interface{}{
				"contentDisposition": "ATTACHMENT",
			},
		}, nil)
	}
	if !repo2Exists {
		nexusRequest(http.MethodPost, "/service/rest/v1/repositories/raw/hosted", &map[string]interface{}{
			"name":   "test-repo-2",
			"online": true,
			"storage": map[string]interface{}{
				"blobStoreName":               "default",
				"strictContentTypeValidation": true,
				"writePolicy":                 "allow_once",
			},
			"cleanup": map[string]interface{}{
				"policyNames": []string{},
			},
			"component": map[string]interface{}{
				"proprietaryComponents": true,
			},
			"raw": map[string]interface{}{
				"contentDisposition": "ATTACHMENT",
			},
		}, nil)
	}

	for _, role := range testRoles {
		resp := nexusRequestWithResponse(http.MethodGet, fmt.Sprintf("/service/rest/v1/security/roles/%v", role["id"]), nil, nil)
		if resp.StatusCode == http.StatusNotFound {
			nexusRequest(http.MethodPost, "/service/rest/v1/security/roles", &role, nil)
		} else {
			roleReq := make(map[string]interface{}, len(role)+1)
			for k, v := range role {
				roleReq[k] = v
			}
			roleReq["source"] = "default"

			nexusRequest(http.MethodPut, fmt.Sprintf("/service/rest/v1/security/roles/%v", role["id"]), &roleReq, nil)
		}
	}

	for _, user := range testUsers {
		var matchingUsers []interface{}
		nexusRequest(http.MethodGet, fmt.Sprintf("/service/rest/v1/security/users?userId=%v", user["userId"]), nil, &matchingUsers)
		if len(matchingUsers) == 0 {
			nexusRequest(http.MethodPost, "/service/rest/v1/security/users", user, nil)
		} else {
			userReq := make(map[string]interface{}, len(user)+1)
			for k, v := range user {
				userReq[k] = v
			}
			userReq["source"] = "default"

			nexusRequest(http.MethodPut, fmt.Sprintf("/service/rest/v1/security/users/%s", user["userId"]), &userReq, nil)
		}
	}

	if os.Getenv("IT_IN_CONTAINER") != "" {
		bopts = append(bopts, chromedp.NoSandbox)
		GinkgoWriter.Printf("!!! WARNING: Sandbox disabled due to containerized environment detected from IT_IN_CONTAINER. This is insecure if this not actually a container!\n")
	}

	biloba.SpinUpChrome(GinkgoT(), bopts...)
	b := biloba.ConnectToChrome(GinkgoT())

	keycloakLogin(b, true, "user-1", "user-1-password")
})

var (
	devMode = false // TODO get this from a env var
	bopts   = []chromedp.ExecAllocatorOption{
		chromedp.ProxyServer("http://localhost:8080"),
		chromedp.Flag("ignore-certificate-errors", "1"),
	}
)

var (
	cluster = gingk8s.KindCluster{
		Name:                   "nexus-oidc-proxy-it",
		KindCommand:            gingk8s.DefaultKind,
		TempDir:                "integration-test",
		ConfigFilePath:         "integration-test/kind.config",
		ConfigFileTemplatePath: "integration-test/kind.config.template",
	}
	clusterClient *http.Client

	watchPods = gingk8s.KubectlWatcher{
		Kind:  "pods",
		Flags: []string{"--all-namespaces"},
	}

	certManagerImages = []*gingk8s.ThirdPartyImage{
		&gingk8s.ThirdPartyImage{Name: "quay.io/jetstack/cert-manager-cainjector:v1.11.1"},
		&gingk8s.ThirdPartyImage{Name: "quay.io/jetstack/cert-manager-controller:v1.11.1"},
		&gingk8s.ThirdPartyImage{Name: "quay.io/jetstack/cert-manager-webhook:v1.11.1"},
	}
	certManager = gingk8s.HelmRelease{
		Name: "cert-manager",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &gingk8s.HelmRepo{
					Name: "jetstack",
					URL:  "https://charts.jetstack.io",
				},
				Name:    "cert-manager",
				Version: "v1.11.1",
			},
		},
		Set: gingk8s.Object{
			"installCRDs":        true,
			"prometheus.enabled": false,
		},
	}

	ingressNginxImage = &gingk8s.ThirdPartyImage{Name: "registry.k8s.io/ingress-nginx/controller:v1.7.0"}
	ingressNginx      = gingk8s.HelmRelease{
		Name: "ingress-nginx",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &gingk8s.HelmRepo{
					Name: "ingress-nginx",
					URL:  "https://kubernetes.github.io/ingress-nginx",
				},
				Name:    "ingress-nginx",
				Version: "4.6.0",
			},
		},
		Values: []gingk8s.NestedObject{
			{
				"controller": gingk8s.NestedObject{
					"service": gingk8s.NestedObject{
						"type": "ClusterIP",
					},
					"extraArgs": gingk8s.NestedObject{
						"default-ssl-certificate": "default/test-cert",
					},
				},
			},
		},
	}

	kubeIngressProxyImage = &gingk8s.ThirdPartyImage{Name: "ghcr.io/meln5674/kube-ingress-proxy:v0.3.0-rc1"}
	kubeIngressProxy      = gingk8s.HelmRelease{
		Name: "kube-ingress-proxy",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Name: "kube-ingress-proxy",
				Repo: &gingk8s.HelmRepo{
					Name: "kube-ingress-proxy",
					URL:  "https://meln5674.github.io/kube-ingress-proxy",
				},
				Version: "v0.3.0-rc1",
			},
		},
		Set: gingk8s.Object{
			"controllerAddresses[0].className": "nginx",
			"controllerAddresses[0].address":   "ingress-nginx-controller.default.svc.cluster.local",
			"hostPort.enabled":                 "true",
		},
		NoWait: true,
	}

	bitnamiRepo = gingk8s.HelmRepo{
		Name: "bitnami",
		URL:  "https://charts.bitnami.com/bitnami",
	}

	bitnamiLegacyRepo = gingk8s.HelmRepo{
		Name: "bitnami-legacy",
		URL:  "https://raw.githubusercontent.com/bitnami/charts/archive-full-index/bitnami",
	}

	certs = gingk8s.KubernetesManifests{
		Name:          "Certs",
		ResourcePaths: []string{"integration-test/certs.yaml"},
		Wait: []gingk8s.WaitFor{
			{
				Resource: "certificate/test-cert",
				For:      gingk8s.StringObject{"condition": "Ready"},
			},
		},
	}

	sonatypeRepo = gingk8s.HelmRepo{
		Name: "sonatype",
		URL:  "https://sonatype.github.io/helm3-charts/",
	}

	nexus = gingk8s.HelmRelease{
		Name: "nexus-repository-manager",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Name: "nexus-repository-manager",
				Repo: &sonatypeRepo,
			},
		},
		Set: gingk8s.Object{
			"fullnameOverride": "nexus",
			"ingress.enabled":  true,
			"ingress.hostRepo": "nexus-api.nexus-oidc-proxy-it.cluster",
		},
	}

	nexusAgain = gingk8s.HelmRelease{
		Name: "nexus-repository-manager",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Name: "nexus-repository-manager",
				Repo: &sonatypeRepo,
			},
		},
		Set: gingk8s.Object{
			"fullnameOverride": "nexus",
			"ingress.enabled":  true,
			"ingress.hostRepo": "nexus-api.nexus-oidc-proxy-it.cluster",
			`nexus.properties.data.nexus\.onboarding\.enabled`:    false,
			`nexus.properties.data.nexus\.scripts\.allowCreation`: true,
			`nexus.properties.override`:                           true,
		},
	}

	nexusAdminPasswordSecret = gingk8s.KubernetesManifests{
		Name: "Nexus Admin Password Secret",
		ResourceObjects: []interface{}{
			gingk8s.NestedObject{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata": gingk8s.NestedObject{
					"name": "nexus-userpass",
				},
				"stringData": gingk8s.NestedObject{
					"username": "admin",
					"password": func(ctx context.Context, cluster gingk8s.Cluster) (string, error) {
						var secret string
						err := gk8s.KubectlExec(ctx, cluster, "deployment/nexus", "cat", []string{"/nexus-data/admin.password"}).WithStreams(gosh.FuncOut(gosh.SaveString(&secret))).Run()
						return secret, err
					},
				},
			},
		},
	}

	nexusOIDCProxyConfig = gingk8s.KubernetesManifests{
		ResourceObjects: []interface{}{
			gingk8s.NestedObject{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata": gingk8s.NestedObject{
					"name": "nexus-oidc-proxy",
				},
				"data": gingk8s.NestedObject{
					"nexus-oidc-proxy.cfg": func(ctx context.Context, cluster gingk8s.Cluster) (string, error) {
						bytes, err := os.ReadFile("integration-test/nexus-oidc-proxy.cfg")
						return string(bytes), err
					},
				},
			},
		},
	}

	nexusOIDCProxyImage = gingk8s.CustomImage{
		Registry:   "local.host",
		Repository: "meln5674/nexus-oidc-proxy",
	}

	nexusOIDCProxy = gingk8s.HelmRelease{
		Name: "nexus-oidc-proxy",
		Chart: &gingk8s.HelmChart{
			LocalChartInfo: gingk8s.LocalChartInfo{
				Path: "deploy/helm/nexus-oidc-proxy",
			},
		},
		Set: gingk8s.Object{
			"credentials.existingSecret.name": "nexus-userpass",
			"config.existingConfigMap.name":   "nexus-oidc-proxy",
			"image.pullPolicy":                "Never",
			"image.repository":                nexusOIDCProxyImage.WithTag(""),
			"image.tag":                       gingk8s.DefaultExtraCustomImageTags[0],
		},
	}

	keycloak = gingk8s.HelmRelease{
		Name: "keycloak",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo:    &bitnamiRepo,
				Name:    "keycloak",
				Version: "14.2.0",
			},
		},
		Set: gingk8s.Object{
			"ingress.enabled":              true,
			"ingress.ingressClassName":     "nginx",
			"ingress.hostname":             "keycloak.nexus-oidc-proxy-it.cluster",
			"ingress.extraTls[0].hosts[0]": "keycloak.nexus-oidc-proxy-it.cluster",
			`ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffer-size`: "1m",
			"auth.adminUser":                  "admin",
			"auth.adminPassword":              "adminPassword",
			"tls.enabled":                     true,
			"tls.usePem":                      true,
			"tls.existingSecret":              "test-cert",
			"tls.keystorePassword":            "keystore-password",
			"tls.truststorePassword":          "truststore-password",
			"service.type":                    "ClusterIP",
			"extraVolumes[0].name":            "home",
			"extraVolumes[0].emptyDir.medium": "Memory",
			"extraVolumeMounts[0].name":       "home",
			"extraVolumeMounts[0].mountPath":  "/home/keycloak",
		},
		UpgradeFlags: []string{"--timeout=10m"},
	}

	keycloakSetupScript []byte // Set during BeforeSuite
	keycloakSetup       = gingk8s.ClusterAction(execKeycloakSetup(
		"keycloak-0",
		"KEYCLOAK_URL=https://keycloak.default.svc.cluster.local",
		"KEYCLOAK_ADMIN_PASSWORD=adminPassword",
		"NEXUS_REALM=integration-test",
		"NEXUS_CLIENT_ID=nexus",
		"NEXUS_CALLBACK_URL=https://nexus.nexus-oidc-proxy-it.cluster/oauth2/callback",
		"CREATE_ROLES='nx-role1 nx-role2'",
		"CREATE_USERS='user-1 user-1-password default-roles-integration-test nx-role1;user-2 user-2-password default-roles-integration-test'",
	))

	oauth2ProxyConfig = gingk8s.KubernetesManifests{
		ResourceObjects: []interface{}{
			gingk8s.NestedObject{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata": gingk8s.NestedObject{
					"name": "oauth2-proxy-cfg",
				},
				"data": gingk8s.NestedObject{
					"oauth2_proxy.cfg": func(ctx context.Context, cluster gingk8s.Cluster) (string, error) {
						bytes, err := os.ReadFile("integration-test/oauth2_proxy.cfg")
						return string(bytes), err
					},
				},
			},
		},
	}

	oauth2Proxy = gingk8s.HelmRelease{
		Name: "oauth2-proxy",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &bitnamiRepo,
				Name: "oauth2-proxy",
			},
		},
		Set: gingk8s.Object{
			"ingress.enabled":              true,
			"ingress.ingressClassName":     "nginx",
			"ingress.hostname":             "nexus.nexus-oidc-proxy-it.cluster",
			"ingress.extraTls[0].hosts[0]": "keycloak.nexus-oidc-proxy-it.cluster",
			"configuration.clientID":       "nexus",
			"configuration.clientSecret": func(ctx context.Context, cluster gingk8s.Cluster) (string, error) {
				var secret string
				err := gk8s.KubectlExec(ctx, cluster, "sts/keycloak", "cat", []string{"/tmp/client-secret"}).WithStreams(gosh.FuncOut(gosh.SaveString(&secret))).Run()
				return secret, err
			},
			"configuration.cookieSecret":        "SbeldwDCUmzHdHGu8j61j6I2fnPjCxyP",
			"configuration.existingConfigmap":   "oauth2-proxy-cfg",
			"extraVolumes[0].name":              "provider-ca",
			"extraVolumes[0].secret.secretName": "test-cert",
			"extraVolumeMounts[0].name":         "provider-ca",
			"extraVolumeMounts[0].mountPath":    "/var/run/secrets/test-certs/ca.crt",
			"extraVolumeMounts[0].subPath":      "ca.crt",
			"hostAliases[0].ip":                 getIngressControllerIP,
			"hostAliases[0].hostnames[0]":       "keycloak.nexus-oidc-proxy-it.cluster",
		},
	}

	testUsers = []map[string]interface{}{
		{"userId": "user1", "firstName": "user", "lastName": "one", "emailAddress": "user1@example.com", "status": "active", "roles": []string{"nx-anonymous"}, "password": "user1Password"},
		{"userId": "user12", "firstName": "user", "lastName": "one", "emailAddress": "user12@example.com", "status": "active", "roles": []string{"nx-anonymous"}, "password": "user12Password"},
	}

	testRoles = []map[string]interface{}{
		{"id": "nx-empty", "name": "Empty", "description": "No Permissions", "privileges": []string{}, "roles": []string{}},
		{"id": "nx-role1", "name": "Role 1", "description": "Role 1", "privileges": []string{"nx-repository-view-raw-test-repo-1-browse"}, "roles": []string{}},
		{"id": "nx-role2", "name": "Role 2", "description": "Role 2", "privileges": []string{"nx-repository-view-raw-test-repo-2-browse"}, "roles": []string{}},
	}

	nexusAdminPassword string
)

func getKeycloakClientSecret(clientID string) func(gingk8s.Gingk8s, context.Context, gingk8s.Cluster) (string, error) {
	return func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) (string, error) {
		var clientSecret string
		err := g.KubectlExec(ctx, cluster, "keycloak-0", "cat", []string{"/tmp/client-secrets/" + clientID}).
			WithStreams(gosh.FuncOut(gosh.SaveString(&clientSecret))).
			Run()
		clientSecret = strings.TrimSuffix(clientSecret, "\n")
		return clientSecret, err
	}
}

func getIngressControllerIP(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) (string, error) {
	var ip string
	err := g.Kubectl(ctx, cluster, "get", "svc", "ingress-nginx-controller", "--template", "{{ .spec.clusterIP }}").
		WithStreams(gosh.FuncOut(gosh.SaveString(&ip))).
		Run()
	return ip, err
}

func execKeycloakSetup(pod string, extraEnv ...string) func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
	return func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
		if len(keycloakSetupScript) == 0 {
			return fmt.Errorf("Keycloak script was not loaded!")
		}
		fullScriptParts := make([]string, len(extraEnv))
		copy(fullScriptParts, extraEnv)
		fullScriptParts = append(fullScriptParts, string(keycloakSetupScript))
		return g.KubectlExec(ctx, cluster, pod, "bash", []string{"-xe"}).
			WithStreams(gosh.StringIn(strings.Join(fullScriptParts, "\n"))).
			Run()
	}
}

func keycloakLogin(b *biloba.Biloba, needCredentials bool, username, password string) {
	GinkgoHelper()
	By("Navigating to the oauth proxy sign-in")
	nexusURL := fmt.Sprintf("https://%s/oauth2/sign_in", oauth2Proxy.Set["ingress.hostname"])
	b.Navigate(nexusURL)
	loginButton := b.XPath("//body/section/div/form/button")
	Eventually(loginButton).Should(b.Exist())

	By("Entering keycloak credentials for typical login")
	b.Click(loginButton)
	if needCredentials {
		Eventually(b.Location, "5s").Should(HavePrefix(fmt.Sprintf("https://%s/", keycloak.Set["ingress.hostname"])))
		b.SetValue("#username", username)
		b.SetValue("#password", password)
		b.Click("#kc-login")
	}

	Eventually(b.Location, "5s").Should(Equal(fmt.Sprintf("https://%s/", oauth2Proxy.Set["ingress.hostname"])))
}

func nexusRequestWithResponse(method string, path string, requestBody interface{}, responseBody interface{}) *http.Response {
	GinkgoHelper()
	var bodyReader io.Reader
	buf := bytes.NewBuffer(make([]byte, 0))
	if requestBody != nil {
		Expect(json.NewEncoder(buf).Encode(requestBody)).To(Succeed())
		bodyReader = buf
	}
	r, err := http.NewRequest(method, "http://nexus:8081"+path, bodyReader)
	Expect(err).ToNot(HaveOccurred())
	r.SetBasicAuth("admin", nexusAdminPassword)
	if requestBody != nil {
		r.Header.Set("content-type", "application/json")
		GinkgoWriter.Printf("%s %s %s\n", r.Method, r.URL.String(), buf.String())
	} else {
		GinkgoWriter.Printf("%s %s\n", r.Method, r.URL.String())
	}
	resp, err := clusterClient.Do(r)
	Expect(err).ToNot(HaveOccurred())
	return resp
}

func nexusRequest(method string, path string, requestBody interface{}, responseBody interface{}) {
	GinkgoHelper()
	resp := nexusRequestWithResponse(method, path, requestBody, responseBody)
	if responseBody == nil {
		Expect(resp.StatusCode).To(BeElementOf(http.StatusOK, http.StatusCreated, http.StatusNoContent))
	} else {
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		Expect(json.NewDecoder(resp.Body).Decode(responseBody)).To(Succeed())
	}
}
