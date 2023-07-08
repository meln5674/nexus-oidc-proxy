#!/bin/bash -xeu

function random-alphanumeric {
    len=$1
    tr -dc A-Za-z0-9 </dev/urandom | head -c "${len}"
}

function ensure-random-alphanumeric {
    path=$1
    len=$2
    if ! [ -f "${path}" ] ; then
        random-alphanumeric "${len}" > "${path}"
    fi
}

function ensure-realm {
    realm=$1
    if ! kcadm.sh get realms -F realm | grep -q '"'"${realm}"'"'; then
        kcadm.sh create realms -s realm="${realm}" -s enabled=true 
    fi

}

function ensure-client {
    realm=$1
    id=$2
    callback_url=$3
    dir=$4
    if ! kcadm.sh get clients \
            -r "${realm}" \
            -q clientId="${id}" \
            -F clientId \
            | tee /dev/stderr \
            | grep -q "${id}" \
            ; then
        client_uid=$(
            kcadm.sh create clients \
                -r "${realm}" \
                -s clientId="${id}" \
                -s clientAuthenticatorType=client-secret \
                -s redirectUris='["'"${callback_url}"'"]'  \
                -i
        )
    else
        client_uid=$(
            kcadm.sh get clients \
                -r "${realm}" \
                -q clientId="${id}" \
                -F id \
                | tee /dev/stderr \
                | grep '"id"' \
                | sed -E 's/.*"id" : "([^"]+)".*/\1/' \
                | tee /dev/stderr
        )
    fi
    mkdir -p "${dir}"
    echo -n "${id}" > "${dir}/client-id"
    if [ -f "${dir}/client-secret" ] ; then
        echo "Client ID/Secret appears to already be configured for ${id}, skipping. Delete the kubernetes secret and re-run the chart if you wish to regenerate the secret"
    else
        kcadm.sh create "clients/${client_uid}/client-secret" \
            -r "${realm}"
    
        kcadm.sh get clients/${client_uid}/client-secret \
            -r "${realm}" \
            -F value \
            | tee /dev/stderr \
            | grep '"value"' \
            | sed -E 's/.*"value" : "([^"]+)".*/\1/' \
            | tee /dev/stderr \
            | tr -d '\n' \
            > "${dir}/client-secret"
    fi
}

function ensure-user {
    realm=$1
    username=$2
    password=$3
    shift 3
    if ! kcadm.sh get users \
            -r "${realm}" \
            -q username="${username}" \
            -F username \
            | tee /dev/stderr \
            | grep -q '"'"${username}"'"' \
            ; then
        user_id=$(
            kcadm.sh create users \
                -r "${realm}" \
                -s username="${username}" \
                -s email="${username}@example.com" \
                -s emailVerified=true \
                -s credentials='[{"type": "password", "value": "test", "temporary": false}]' \
                -s enabled=true
        )
    else
        user_id=$(
            kcadm.sh get users \
                -r "${realm}" \
                -q username="${username}" \
                -F id \
                | tee /dev/stderr \
                | grep '"id"' \
                | sed -E 's/.*"id" : "([^"]+)".*/\1/' \
                | tee /dev/stderr
        )
    fi

    for role in "$@"; do
        kcadm.sh add-roles \
               -r "${realm}" \
               --rolename "${role}" \
               --uusername "${username}"
    done
}

function ensure-role {
    realm=$1
    role=$2
    if ! kcadm.sh get "roles/${role}" \
            -r "${realm}" \
            -F name \
            ; then
        kcadm.sh create roles \
            -r "${realm}" \
            -s name="${role}" \
            -i
    fi
}

ensure-random-alphanumeric "/tmp/cookie-secret" 32

rm -f /tmp/trust.jks

keytool -import \
    -keystore /tmp/trust.jks \
    -storepass truststore-password \
    -file /opt/bitnami/keycloak/certs/tls.crt \
    -noprompt
kcadm.sh config truststore \
    --trustpass truststore-password /tmp/trust.jks

while ! curl -v --cacert /opt/bitnami/keycloak/certs/tls.crt "${KEYCLOAK_URL}" ; do
    echo "Keycloak is not yet ready, waiting..."
    sleep 15
done

kcadm.sh config credentials \
    --server "${KEYCLOAK_URL}" \
    --realm master \
    --user admin \
    --password "${KEYCLOAK_ADMIN_PASSWORD}" \
    --client admin-cli


ensure-realm "${NEXUS_REALM}"
ensure-client "${NEXUS_REALM}" "${NEXUS_CLIENT_ID}" "${NEXUS_CALLBACK_URL}" /tmp

for role in ${CREATE_ROLES:-}; do
    ensure-role "${NEXUS_REALM}" "${role}"
done

while read -r username password roles ; do
    ensure-user "${NEXUS_REALM}" "${username}" "${password}" ${roles}
done <<< "${CREATE_USERS:-}"
