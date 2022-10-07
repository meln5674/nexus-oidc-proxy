#!/bin/bash -xe

# Ensure datasets are downloaded
# Create a KinD cluster with the repo checkout mounted
# Install cert-manager
# Create wildcard cert that also doubles as keycloak internal cert
# Install secrets-operator
# Create derived secret that generates keycloak cert from cert-manager cert
# Install nginx ingress controller with default cert as wildcard
# Install keycloak set to use generated cert
# Install nexus without ingress
# Install proxy configured with nexus as upstream configured to set RUT auth header based on expected header from oauth2 proxy, and with a sample set of role templates
# Install oauth2-proxy configured to authenticate with keycloak and send both username and access token (claims JWT) to proxy as upstream
# Run job to create users w/ roles in keycloak
# Run job to create matching roles in nexus
# Run job to upload and download artifacts from nexus via http scraping of page

export KUBECONFIG=${KUBECONFIG:-$PWD/integration-test/kubeconfig}
KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-nexus-oidc-proxy}
if ! kind get clusters | grep -q "${KIND_CLUSTER_NAME}" ; then
    sed "s/hostPath: .*/hostPath: '${PWD//\//\\/}'/" < integration-test/kind.config.template > integration-test/kind.config

    kind create cluster --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}" --config integration-test/kind.config
    if [ -z "${INTEGRATION_TEST_NO_CLEANUP}" ]; then
        trap "kind delete cluster --name '${KIND_CLUSTER_NAME}'" EXIT
    fi
fi

helm repo add jetstack https://charts.jetstack.io
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add sonatype https://sonatype.github.io/helm3-charts/
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

CERT_MANAGER_ARGS=(
    --set installCRDs=true
    --set prometheus.enabled=false
)

helm upgrade --install --wait cert-manager jetstack/cert-manager "${CERT_MANAGER_ARGS[@]}"

kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: test-cert
spec:
  commonName: test-cert
  secretName: test-cert
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
  dnsNames:
  - '*.nexus-oidc-proxy-it'
  - keycloak.default.svc.cluster.local
  - keycloak-0.keycloak.default.svc.cluster.local
  - keycloak-0
EOF

kubectl wait certificate/test-cert --for=condition=ready 

make -C ../secrets-operator docker-build install deploy IMG=meln5674/secrets-operator:latest
kubectl -n secrets-operator-system patch deploy/secrets-operator-controller-manager --type=json --patch='[{"op":"replace","path":"/spec/template/spec/containers/1/imagePullPolicy","value":"Never"}]'
kind load docker-image --name ${KIND_CLUSTER_NAME} meln5674/secrets-operator:latest
kubectl -n secrets-operator-system rollout restart deploy/secrets-operator-controller-manager
kubectl -n secrets-operator-system rollout status deploy/secrets-operator-controller-manager

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: impersonator
  namespace: default
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["impersonate"]
  resourceNames: ["default"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secrets-operator-impersonation
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: impersonator
subjects:
- kind: ServiceAccount
  name: secrets-operator-controller-manager
  namespace: secrets-operator-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secrets-operator
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: secrets-operator-manager-role
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
---
apiVersion: secrets.meln5674.github.com/v1alpha1
kind: DerivedSecret
metadata:
  name: keycloak-certs
  namespace: default
spec:
  references:
  - name: testCert
    secretRef:
      name: test-cert
  data:
    ca.crt:
      template: |-
        {{ index .References.testCert "ca.crt" | b64bin }}
    keycloak-0.crt: 
      template: |-
        {{ index .References.testCert "tls.crt" | b64bin }}
    keycloak-0.key:
      template: |-
        {{ index .References.testCert "tls.key" | b64bin }}
  serviceAccountName: default
EOF

INGRESS_NGINX_ARGS=(
    --set controller.service.type=ClusterIP
    --set controller.kind=DaemonSet
    --set controller.hostPort.enabled=true
    --set controller.extraArgs.default-ssl-certificate=default/test-cert
)

helm upgrade --install --wait ingress-nginx ingress-nginx/ingress-nginx "${INGRESS_NGINX_ARGS[@]}"

# Nginx doesn't like answer webhook requests right away for some reason
while ! kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sentinel
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: dummy
            port:
              number: 80
EOF
do
    sleep 5
done

kubectl delete ingress sentinel

NEXUS_ARGS=(
    --set fullnameOverride=nexus
    --set ingress.enabled=true
    --set ingress.hostRepo=nexus-api.nexus-oidc-proxy-it
)

if ! helm get notes nexus >/dev/null ; then
    # https://github.com/sonatype/helm3-charts/issues/68
    # tl;dr nexus chart maintainers don't have to care what people who aren't paying them care
    helm upgrade --install --wait nexus sonatype/nexus-repository-manager "${NEXUS_ARGS[@]}"
fi

NEXUS_ARGS+=(
    --set "nexus.properties.data.nexus\.onboarding\.enabled"=false
    --set "nexus.properties.data.nexus\.scripts\.allowCreation"=true
    --set nexus.properties.override=true
)

helm upgrade --install --wait nexus sonatype/nexus-repository-manager "${NEXUS_ARGS[@]}"

NEXUS_ADMIN_PASSWORD=$(kubectl exec deployment/nexus -- cat /nexus-data/admin.password)

kubectl get secret nexus-userpass >/dev/null || kubectl create secret generic nexus-userpass --from-literal=username=admin --from-literal=password=${NEXUS_ADMIN_PASSWORD}

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: nexus-oidc-proxy
data:
  nexus-oidc-proxy.cfg: |
$(set +x; while IFS= read -r line; do echo "    ${line}" ; done < integration-test/nexus-oidc-proxy.cfg; set +x)
EOF

IMG_TAG=testing-$(date +%s)
docker build -t meln5674/nexus-oidc-proxy:${IMG_TAG} .
kind load docker-image --name ${KIND_CLUSTER_NAME} meln5674/nexus-oidc-proxy:${IMG_TAG}

NEXUS_OIDC_PROXY_ARGS=(
    --set credentials.existingSecret.name=nexus-userpass
    --set config.existingConfigMap.name=nexus-oidc-proxy
    --set image.pullPolicy=Never
    --set image.repository=meln5674/nexus-oidc-proxy
    --set image.tag=${IMG_TAG}
)

helm upgrade --install --wait nexus-oidc-proxy ./deploy/helm/nexus-oidc-proxy "${NEXUS_OIDC_PROXY_ARGS[@]}"

KEYCLOAK_ARGS=(
    --set ingress.enabled=true
    --set ingress.ingressClassName=nginx
    --set ingress.hostname=keycloak.nexus-oidc-proxy-it
    --set ingress.extraTls[0].hosts[0]=keycloak.nexus-oidc-proxy-it
    --set auth.adminUser=admin
    --set auth.adminPassword=adminPassword
    --set auth.tls.enabled=true
    --set auth.tls.usePem=true
    --set auth.tls.existingSecret=keycloak-certs
    --set auth.tls.keystorePassword=keystore-password
    --set auth.tls.truststorePassword=truststore-password
    --set service.type=ClusterIP
    # Need these for the keycloak cli to work
    --set extraVolumes[0].name=home
    --set extraVolumes[0].emptyDir.medium=Memory
    --set extraVolumeMounts[0].name=home
    --set extraVolumeMounts[0].mountPath=/home/keycloak
    # This one takes forever, who knows why
    --timeout=10m
)

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: oauth2-proxy-cfg
data:
  oauth2_proxy.cfg: |
$(set +x; while IFS= read -r line; do echo "    ${line}" ; done < integration-test/oauth2_proxy.cfg; set +x)
EOF

helm upgrade --install --wait keycloak bitnami/keycloak "${KEYCLOAK_ARGS[@]}"

if ! kubectl get secret oidc-client >/dev/null ; then
    kubectl exec -it keycloak-0 -- bash -xe <<EOF
    kcadm.sh config credentials --server https://keycloak.default.svc.cluster.local/ --realm master --user admin --password adminPassword --client admin-cli --truststore /opt/bitnami/keycloak/certs/keycloak.truststore.jks --trustpass truststore-password
    if ! kcadm.sh get realms -F realm --truststore /opt/bitnami/keycloak/certs/keycloak.truststore.jks --trustpass truststore-password | grep -q '"integration-test"'; then
        kcadm.sh create realms -s realm=integration-test -s enabled=true --truststore /opt/bitnami/keycloak/certs/keycloak.truststore.jks --trustpass truststore-password
    fi
    if ! kcadm.sh get clients -r integration-test -q clientId=client-id -F clientId  --truststore /opt/bitnami/keycloak/certs/keycloak.truststore.jks --trustpass truststore-password | grep -q '"client-id"' ; then
        client_uid=\$(kcadm.sh create clients -r integration-test -s clientId=client-id -s clientAuthenticatorType=client-secret -s "redirectUris=[\"https://nexus.nexus-oidc-proxy-it/oauth2/callback\"]" --truststore /opt/bitnami/keycloak/certs/keycloak.truststore.jks --trustpass truststore-password -i)
        kcadm.sh create clients/\${client_uid}/client-secret -r integration-test -F  --truststore /opt/bitnami/keycloak/certs/keycloak.truststore.jks --trustpass truststore-password
    fi
    kcadm.sh get clients/\${client_uid}/client-secret -r integration-test -F value --truststore /opt/bitnami/keycloak/certs/keycloak.truststore.jks --trustpass truststore-password | grep '"value"' | sed -E 's/.*"value" : "([^"]+)".*/\1/' > /tmp/client-secret
EOF

    client_secret=$(kubectl exec keycloak-0 -- cat /tmp/client-secret)
    kubectl create secret generic oidc-client --from-literal client_secret=${client_secret}
else
    client_secret=$(kubectl get secret oidc-client --template '{{ .data.client_secret }}' | base64 -d) 
fi

OAUTH2_PROXY_ARGS=(
    --set ingress.enabled=true
    --set ingress.ingressClassName=nginx
    --set ingress.hostname=nexus.nexus-oidc-proxy-it
    --set ingress.extraTls[0].hosts[0]=keycloak.nexus-oidc-proxy-it
    --set configuration.clientID=client-id
    --set configuration.clientSecret=${client_secret}
    --set configuration.cookieSecret=SbeldwDCUmzHdHGu8j61j6I2fnPjCxyP
    --set configuration.existingConfigmap=oauth2-proxy-cfg
    --set extraVolumes[0].name=provider-ca
    --set extraVolumes[0].secret.secretName=test-cert
    --set extraVolumeMounts[0].name=provider-ca
    --set extraVolumeMounts[0].mountPath=/var/run/secrets/test-certs/ca.crt
    --set extraVolumeMounts[0].subPath=ca.crt
    --set hostAliases[0].ip=$(kubectl get svc ingress-nginx-controller | awk '{ print $3 }' | tail -n -1)
    --set hostAliases[0].hostnames[0]=keycloak.nexus-oidc-proxy-it
)

helm upgrade --install --wait oauth2-proxy bitnami/oauth2-proxy "${OAUTH2_PROXY_ARGS[@]}"

kubectl replace --force -f - <<EOF

apiVersion: batch/v1
kind: Job
metadata:
  name: nexus-oicd-proxy-it-setup
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: curl
        image: docker.io/alpine/curl:latest
        command: [sh, -exuc]
        args:
        - |
            while read -r user userJSON ; do
                matchingUsers=\$(curl -v -f -u admin:${NEXUS_ADMIN_PASSWORD} "http://nexus:8081/service/rest/v1/security/users?userId=\${user}")
                if echo "\${matchingUsers}" | grep -Eq "\\"userId\\"\\s*:\\s*\\"\${user}\""; then
                    curl -v -f -u admin:${NEXUS_ADMIN_PASSWORD} "http://nexus:8081/service/rest/v1/security/users/\${user}" \
                        -X PUT \
                        -H content-type:application/json \
                        --data-raw "\${userJSON%"}"},\\"source\\":\\"default\\"}"
                else
                    curl -v -f -u admin:${NEXUS_ADMIN_PASSWORD} http://nexus:8081/service/rest/v1/security/users \
                        -X POST \
                        -H content-type:application/json \
                        --data-raw "\${userJSON}"
                fi
            done < /mnt/host/nexus-oidc-proxy/integration-test/users.txt
            while read -r role roleJSON ; do
                if curl -v -f -u admin:${NEXUS_ADMIN_PASSWORD} "http://nexus:8081/service/rest/v1/security/roles/\${role}"; then
                    curl -v -f -u admin:${NEXUS_ADMIN_PASSWORD} "http://nexus:8081/service/rest/v1/security/roles/\${role}" \
                        -X PUT \
                        -H content-type:application/json \
                        --data-raw "\${roleJSON}"
                else
                    curl -v -f -u admin:${NEXUS_ADMIN_PASSWORD} http://nexus:8081/service/rest/v1/security/roles \
                        -X POST \
                        -H content-type:application/json \
                        --data-raw "\${roleJSON%"}"},\\"source\\":\\"default\\"}"
                fi
            done < /mnt/host/nexus-oidc-proxy/integration-test/roles.txt

        volumeMounts:
        - name: datasets
          mountPath: /mnt/host/nexus-oidc-proxy/integration-test/
      volumes:
      - name: datasets
        hostPath:
          path: /mnt/host/nexus-oidc-proxy/integration-test/

EOF



