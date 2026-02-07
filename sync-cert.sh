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
  echo "--- Start Sync: Secret ${SYNC_SECRET_NAMESPACE}/${SYNC_SECRET_NAME} ---"

  # 1. Fetch Secret
  kubectl get secret "${SYNC_SECRET_NAME}" -n "${SYNC_SECRET_NAMESPACE}" -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/tls.crt
  kubectl get secret "${SYNC_SECRET_NAME}" -n "${SYNC_SECRET_NAMESPACE}" -o jsonpath='{.data.tls\.key}' | base64 -d > /tmp/tls.key

  # 2. Calculate Local SHA-1 Fingerprint (Uppercase, no colons)
  LOCAL_FP=$(openssl x509 -noout -fingerprint -sha1 -in /tmp/tls.crt | sed 's/://g' | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
  echo "Local Certificate Fingerprint: ${LOCAL_FP}"

  # 3. Search for existing cert in Alibaba CAS using the Fingerprint
  # Note: OrderType=UPLOAD ensures we only look at certs you uploaded manually
  EXISTING_JSON=$(aliyun cas ListUserCertificateOrder --region "${ALIBABA_REGION_ID}" --OrderType UPLOAD --Status ISSUED)
  
  # Use jq to find the CertificateId matching our local fingerprint
  CERT_ID=$(echo "$EXISTING_JSON" | jq -r --arg fp "$LOCAL_FP" '.CertificateOrderList[] | select(.Fingerprint == $fp) | .CertificateId' | head -n 1)

  if [ -z "$CERT_ID" ] || [ "$CERT_ID" == "null" ]; then
    NEW_CERT_NAME="${CERT_NAME_PREFIX}-$(date +%Y-%m-%d)"
    echo "No matching cert found. Uploading as: ${NEW_CERT_NAME}..."
    
    UPLOAD_RES=$(aliyun waf-openapi CreateCerts \
      --region "${ALIBABA_REGION_ID}" \
      --CertName "${NEW_CERT_NAME}" \
      --CertContent "$(cat /tmp/tls.crt)" \
      --CertKey "$(cat /tmp/tls.key)")
    
    CERT_ID=$(echo "$UPLOAD_RES" | jq -r '.CertId')
    echo "Uploaded successfully. New ID: ${CERT_ID}"
  else
    echo "Matching certificate found in CAS. ID: ${CERT_ID}"
  fi

  # 4. Construct WAF-specific Certificate ID (e.g., "xxxx-cn-hangzhou")
  WAF_CERT_ID="${CERT_ID}-${ALIBABA_REGION_ID}"

  # 5. Build WAF Listen JSON payload
  # We use jq to handle numeric/boolean/string types correctly for the API
  LISTEN_JSON=$(jq -n \
    --arg tls "$TLS_VERSION" \
    --argjson tls3 "$ENABLE_TLS_V3" \
    --argjson cipher "$CIPHER_SUITE" \
    --arg proto "$PROTOCOL" \
    --arg cert "$WAF_CERT_ID" \
    --argjson h2 "$HTTP2_ENABLED" \
    --arg clb "$ALIBABA_CLB_ID" \
    '{
      TLSVersion: $tls,
      EnableTLSv3: $tls3,
      CipherSuite: $cipher,
      Protocol: $proto,
      Certificates: [{CertificateId: $cert, AppliedType: "default"}],
      Http2Enabled: $h2,
      ResourceInstanceId: $clb
    }')

  # 6. Execute WAF Update using waf-openapi
  echo "Updating WAF Cloud Resource for CLB: ${ALIBABA_CLB_ID}..."
  aliyun waf-openapi ModifyCloudResource \
    --region "${ALIBABA_REGION_ID}" \
    --RegionId "${ALIBABA_REGION_ID}" \
    --InstanceId "${ALIBABA_WAF_INSTANCE_ID}" \
    --Listen "$LISTEN_JSON"

  echo "Sync process finished successfully."
fi