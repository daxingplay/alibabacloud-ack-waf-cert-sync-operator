#!/usr/bin/env bash

# Registration for Shell-operator
if [[ $1 == "--config" ]] ; then
  cat <<EOF
configVersion: v1
kubernetes:
- apiVersion: v1
  kind: Secret
  nameSelector:
    matchNames: [ "${SYNC_SECRET_NAME}" ]
  namespace:
    nameSelector:
      matchNames: [ "${SYNC_SECRET_NAMESPACE}" ]
  executeHookOnEvent: [ "Added", "Modified" ]
EOF
else
  set -euo pipefail
  # Avoid ANSI escape codes in output so shell-operator JSON logging does not break
  export TERM=dumb

  # Configure Alibaba Cloud CLI with RRSA (OIDC). Prefer ACK-injected env vars
  # (ALIBABA_CLOUD_*) from ack-pod-identity-webhook; fall back to manual ALIBABA_* names.
  # See: https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services
  OIDC_PROVIDER_ARN="${ALIBABA_CLOUD_OIDC_PROVIDER_ARN:-${ALIBABA_OIDC_PROVIDER_ARN:-}}"
  RAM_ROLE_ARN="${ALIBABA_CLOUD_ROLE_ARN:-${ALIBABA_RAM_ROLE_ARN:-}}"
  OIDC_TOKEN_FILE="${ALIBABA_CLOUD_OIDC_TOKEN_FILE:-${ALIBABA_OIDC_TOKEN_FILE:-}}"
  if [[ -n "$OIDC_PROVIDER_ARN" && -n "$RAM_ROLE_ARN" && -n "$OIDC_TOKEN_FILE" ]]; then
    PROFILE="${ALIBABA_OIDC_PROFILE:-default}"
    REGION="${ALIBABA_REGION_ID:-cn-hangzhou}"
    ROLE_SESSION_NAME="${ALIBABA_ROLE_SESSION_NAME:-cert-sync}"
    if [[ ! -f "$OIDC_TOKEN_FILE" ]]; then
      echo "ERROR: OIDC token file not found: ${OIDC_TOKEN_FILE}" >&2
      exit 1
    fi
    aliyun configure set \
      --profile "${PROFILE}" \
      --mode OIDC \
      --oidc-provider-arn "${OIDC_PROVIDER_ARN}" \
      --oidc-token-file "${OIDC_TOKEN_FILE}" \
      --ram-role-arn "${RAM_ROLE_ARN}" \
      --role-session-name "${ROLE_SESSION_NAME}" \
      --region "${REGION}"
    export ALIBABA_CLI_PROFILE="${PROFILE}"
  fi

  echo "--- Start Sync: Secret ${SYNC_SECRET_NAMESPACE}/${SYNC_SECRET_NAME} ---"

  # 1. Fetch Secret
  kubectl get secret "${SYNC_SECRET_NAME}" -n "${SYNC_SECRET_NAMESPACE}" -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/tls.crt
  kubectl get secret "${SYNC_SECRET_NAME}" -n "${SYNC_SECRET_NAMESPACE}" -o jsonpath='{.data.tls\.key}' | base64 -d > /tmp/tls.key

  # 2. Calculate Local SHA-1 Fingerprint (Uppercase, no colons)
  LOCAL_FP=$(openssl x509 -noout -fingerprint -sha1 -in /tmp/tls.crt | sed 's/://g' | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
  echo "Local Certificate Fingerprint: ${LOCAL_FP}"

  # 3. Search for existing cert in Alibaba CAS using the Fingerprint. Strip ANSI from stderr.
  # Note: OrderType=UPLOAD ensures we only look at certs you uploaded manually
  EXISTING_JSON=$(aliyun cas ListUserCertificateOrder --region "${ALIBABA_REGION_ID}" --OrderType UPLOAD --Status ISSUED 2> >(sed 's/\x1b\[[0-9;]*m//g' >&2)) || {
    echo "ERROR: aliyun ListUserCertificateOrder failed. Check RRSA/credentials and region." >&2
    exit 1
  }

  # Use jq to find the CertificateId matching our local fingerprint
  CERT_ID=$(echo "$EXISTING_JSON" | jq -r --arg fp "$LOCAL_FP" '.CertificateOrderList[] | select(.Fingerprint == $fp) | .CertificateId' | head -n 1)

  if [ -z "$CERT_ID" ] || [ "$CERT_ID" == "null" ]; then
    NEW_CERT_NAME="${CERT_NAME_PREFIX}-$(date +%Y-%m-%d)"
    echo "No matching cert found. Uploading as: ${NEW_CERT_NAME}..."

    UPLOAD_RES=$(aliyun waf-openapi CreateCerts \
      --region "${ALIBABA_REGION_ID}" \
      --CertName "${NEW_CERT_NAME}" \
      --CertContent "$(cat /tmp/tls.crt)" \
      --CertKey "$(cat /tmp/tls.key)" 2> >(sed 's/\x1b\[[0-9;]*m//g' >&2)) || {
      echo "ERROR: aliyun CreateCerts failed. Check RRSA/credentials and permissions." >&2
      exit 1
    }

    CERT_ID=$(echo "$UPLOAD_RES" | jq -r '.CertId')
    if [ -z "$CERT_ID" ] || [ "$CERT_ID" == "null" ]; then
      echo "ERROR: CreateCerts did not return a valid CertId. Output: ${UPLOAD_RES}" >&2
      exit 1
    fi
    echo "Uploaded successfully. New ID: ${CERT_ID}"
  else
    echo "Matching certificate found in CAS. ID: ${CERT_ID}"
  fi

  # 4. Construct WAF-specific Certificate ID (e.g., "xxxx-cn-hangzhou")
  WAF_CERT_ID="${CERT_ID}-${ALIBABA_REGION_ID}"

  # 5. Build WAF Listen JSON payload. ResourceProduct (e.g. clb4) and Port are required by the API.
  TLS_VERSION="${TLS_VERSION:-tlsv1.2}"
  ENABLE_TLS_V3="${ENABLE_TLS_V3:-true}"
  CIPHER_SUITE="${CIPHER_SUITE:-2}"
  PROTOCOL="${PROTOCOL:-https}"
  HTTP2_ENABLED="${HTTP2_ENABLED:-true}"
  RESOURCE_PRODUCT="${RESOURCE_PRODUCT:-clb4}"
  PORT="${PORT:-443}"
  LISTEN_JSON=$(jq -n \
    --arg tls "$TLS_VERSION" \
    --argjson tls3 "$ENABLE_TLS_V3" \
    --argjson cipher "$CIPHER_SUITE" \
    --arg proto "$PROTOCOL" \
    --arg cert "$WAF_CERT_ID" \
    --argjson h2 "$HTTP2_ENABLED" \
    --arg clb "$ALIBABA_CLB_ID" \
    --arg product "$RESOURCE_PRODUCT" \
    --argjson port "$PORT" \
    '{
      TLSVersion: $tls,
      EnableTLSv3: $tls3,
      CipherSuite: $cipher,
      Protocol: $proto,
      Certificates: [{CertificateId: $cert, AppliedType: "default"}],
      Http2Enabled: $h2,
      ResourceProduct: $product,
      ResourceInstanceId: $clb,
      Port: $port
    }')

  # 6. Execute WAF Update using waf-openapi. Strip ANSI from aliyun stderr so shell-operator JSON log does not break.
  echo "Updating WAF Cloud Resource for CLB: ${ALIBABA_CLB_ID}..."
  aliyun waf-openapi ModifyCloudResource \
    --region "${ALIBABA_REGION_ID}" \
    --RegionId "${ALIBABA_REGION_ID}" \
    --InstanceId "${ALIBABA_WAF_INSTANCE_ID}" \
    --Listen "$LISTEN_JSON" 2> >(sed 's/\x1b\[[0-9;]*m//g' >&2) || {
    echo "ERROR: aliyun ModifyCloudResource failed. Check RRSA/credentials, WAF/CLB IDs, ResourceProduct and Port." >&2
    exit 1
  }

  echo "Sync process finished successfully."
fi