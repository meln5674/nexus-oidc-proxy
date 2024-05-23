package main_test

import (
	"context"
	"net/http"
	"strings"

	"github.com/meln5674/gingk8s"
	"github.com/meln5674/gosh"
	"github.com/onsi/biloba"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type tcase struct {
	name                 string
	oauth2ProxyConfig    *gingk8s.KubernetesManifests
	nexusOIDCProxyConfig *gingk8s.KubernetesManifests
}

var _ = Describe("The Nexus OIDC Proxy", Ordered, func() {

	cases := []tcase{
		{
			name:                 "Access Token via Raw Header",
			oauth2ProxyConfig:    &oauth2ProxyConfigRawAccess,
			nexusOIDCProxyConfig: &nexusOIDCProxyConfigRawAccess,
		},
		{
			name:                 "ID Token via Bearer Header",
			oauth2ProxyConfig:    &oauth2ProxyConfigIDBearer,
			nexusOIDCProxyConfig: &nexusOIDCProxyConfigIDBearer,
		},
	}

	for _, cas := range cases {

		When("Using "+cas.name, Ordered, func() {
			BeforeAll(func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)
				gk8s := gk8s.ForSpec()

				oauth2ProxyConfigID := gk8s.Manifests(clusterID, cas.oauth2ProxyConfig)
				nexusOIDCProxyConfigID := gk8s.Manifests(clusterID, cas.nexusOIDCProxyConfig)

				oauth2ProxyID := gk8s.Release(clusterID, &oauth2Proxy, oauth2ProxyConfigID)
				nexusOIDCProxyID := gk8s.Release(clusterID, &nexusOIDCProxy, nexusOIDCProxyConfigID)

				gk8s.ClusterAction(clusterID, "Restart oauth2 proxy", gingk8s.ClusterAction(func(gk8s gingk8s.Gingk8s, ctx context.Context, c gingk8s.Cluster) error {
					return gosh.And(
						gk8s.Kubectl(ctx, c, "rollout", "restart", "deploy/oauth2-proxy"),
						gk8s.Kubectl(ctx, c, "rollout", "status", "deploy/oauth2-proxy"),
					).Run()
				}), oauth2ProxyID)
				gk8s.ClusterAction(clusterID, "Restart nexus oidc proxy", gingk8s.ClusterAction(func(gk8s gingk8s.Gingk8s, ctx context.Context, c gingk8s.Cluster) error {
					return gosh.And(
						gk8s.Kubectl(ctx, c, "rollout", "restart", "deploy/nexus-oidc-proxy"),
						gk8s.Kubectl(ctx, c, "rollout", "status", "deploy/nexus-oidc-proxy"),
					).Run()
				}), nexusOIDCProxyID)

				gk8s.Setup(ctx)

				Expect(execKeycloakSetup(
					"keycloak-0",
					"KEYCLOAK_URL=https://keycloak.default.svc.cluster.local",
					"KEYCLOAK_ADMIN_PASSWORD=adminPassword",
					"NEXUS_REALM=integration-test",
					"NEXUS_CLIENT_ID=nexus",
					"NEXUS_CALLBACK_URL=https://nexus.nexus-oidc-proxy-it.cluster/oauth2/callback",
					"CREATE_ROLES='nx-role1 nx-role2'",
					"CREATE_USERS='user-1 user-1-password nx-role1'",
					"RECREATE_USER=1",
				)(gk8s, ctx, &cluster)).To(Succeed())
			})
			It("Should start", func() {
				b = biloba.ConnectToChrome(GinkgoT())
				keycloakLogin(true)

				b.Navigate("https://nexus.nexus-oidc-proxy-it.cluster")

				welcomeImg := `img.nxrm-welcome__logo`
				Eventually(welcomeImg, "30s").Should(b.Exist())
			})

			It("Should show the user as logged in", func() {
				b = biloba.ConnectToChrome(GinkgoT())
				keycloakLogin(true)

				b.Navigate("https://nexus.nexus-oidc-proxy-it.cluster")

				accountButton := `a[data-name='user'] > span > span > span.x-btn-inner`

				Eventually(accountButton, "15s").Should(b.Exist())
				Expect(accountButton).To(b.HaveInnerText("user-1"))
			})

			It("Should allow generating, and logging into the API with, a token", func(ctx context.Context) {
				b = biloba.ConnectToChrome(GinkgoT())
				keycloakLogin(true)

				b.Navigate("https://nexus.nexus-oidc-proxy-it.cluster/token")

				generateButton := `input`

				Eventually(generateButton, "5s").Should(b.Exist())
				b.Click(generateButton)

				Eventually(`body`, "5s").Should(b.HaveInnerText(ContainSubstring("Your new token is: ")))

				bodyLines := strings.Split(b.InnerText(`body`), "\n")
				Expect(bodyLines).To(HaveLen(4))
				tokenLine := bodyLines[2]

				token := strings.TrimPrefix(tokenLine, "Your new token is: ")

				GinkgoWriter.Println("Token is", token)

				b.Navigate("https://nexus-api.nexus-oidc-proxy-it.cluster")
				welcomeImg := `img.nxrm-welcome__logo`
				Eventually(welcomeImg, "15s").Should(b.Exist())

				signInButton := `a[data-componentid='nx-header-signin-1145']`

				b.Click(signInButton)

				usernameField := `input[name='username']`
				passwordField := `input[name='password']`
				submitButtonXPath := `//div[contains(@class, 'x-window')]//span[text() = 'Sign in']`
				disabledSubmitButton := `a.x-btn-disabled`

				Eventually(usernameField, "5s").Should(b.Exist())
				Eventually(passwordField, "5s").Should(b.Exist())
				Eventually(submitButtonXPath, "5s").Should(b.Exist())
				Eventually(disabledSubmitButton, "5s").Should(b.Exist())
				b.SetValue(usernameField, "user-1")
				b.SetValue(passwordField, token)
				Eventually(disabledSubmitButton).ShouldNot(b.Exist())
				By("Clicking the button")
				b.Click(submitButtonXPath)
				Eventually(submitButtonXPath).ShouldNot(b.Exist())

				accountButton := `a[data-name='user'] > span > span > span.x-btn-inner`

				Eventually(accountButton, "15s").Should(b.Exist())
				Eventually(accountButton, "15s").Should(b.HaveInnerText("user-1"))
			})

			browseButton := `tr[data-qtip='Browse assets and components']`
			testRepo1XPath := `//div[text() = 'test-repo-1']`
			testRepo2XPath := `//div[text() = 'test-repo-2']`
			It("should show repos granted to the user by their roles", func(ctx context.Context) {
				b = biloba.ConnectToChrome(GinkgoT())
				keycloakLogin(true)

				b.Navigate("https://nexus.nexus-oidc-proxy-it.cluster")

				Eventually(browseButton, "15s").Should(b.Exist())
				b.Click(browseButton)

				Eventually(testRepo1XPath, "5s").Should(b.Exist())
				Expect(testRepo2XPath).ToNot(b.Exist())
				Expect(execKeycloakSetup(
					"keycloak-0",
					"KEYCLOAK_URL=https://keycloak.default.svc.cluster.local",
					"KEYCLOAK_ADMIN_PASSWORD=adminPassword",
					"NEXUS_REALM=integration-test",
					"NEXUS_CLIENT_ID=nexus",
					"NEXUS_CALLBACK_URL=https://nexus.nexus-oidc-proxy-it.cluster/oauth2/callback",
					"CREATE_ROLES='nx-role1 nx-role2'",
					"CREATE_USERS='user-1 user-1-password nx-role1 nx-role2'",
					"RECREATE_USER=1",
				)(gk8s, ctx, &cluster)).To(Succeed())

				b = biloba.ConnectToChrome(GinkgoT())
				b.NavigateWithStatus("https://nexus.nexus-oidc-proxy-it.cluster/oauth2/sign_out", http.StatusForbidden)

				keycloakLogin(true)

				b.Navigate("https://nexus.nexus-oidc-proxy-it.cluster")
				Eventually(browseButton, "15s").Should(b.Exist())
				b.Click(browseButton)
				Eventually(testRepo1XPath, "5s").Should(b.Exist())
				Expect(testRepo2XPath).To(b.Exist())
			})
		})

	}
})