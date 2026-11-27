#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The agent checks ClusterIP egress before service translation.
dns_ip="$(kubectl -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')"
if [[ ! "$dns_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'The example requires an IPv4 kube-system/kube-dns Service.\n' >&2
  exit 1
fi

umask 077
certs="$(mktemp -d)"
trap 'rm -rf "$certs"' EXIT
cat > "$certs/ca.cnf" <<'CA'
[req]
prompt = no
distinguished_name = dn
x509_extensions = extensions
[dn]
CN = ztap-telemetry-example-ca
[extensions]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
CA
openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
  -config "$certs/ca.cnf" \
  -keyout "$certs/ca.key" -out "$certs/ca.crt"
cat > "$certs/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:otel-collector.ztap-telemetry.svc
EXT
cat > "$certs/client.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXT
for role in server client; do
  openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=ztap-otel-$role" \
    -keyout "$certs/$role.key" -out "$certs/$role.csr"
  openssl x509 -req -sha256 -days 30 -in "$certs/$role.csr" -CA "$certs/ca.crt" \
    -CAkey "$certs/ca.key" -CAcreateserial -out "$certs/$role.crt" -extfile "$certs/$role.ext"
done
put_secret() {
  kubectl -n "$1" create secret generic "$2" --dry-run=client -o yaml \
    --from-file=ca.crt="$certs/ca.crt" --from-file=tls.crt="$certs/$3.crt" \
    --from-file=tls.key="$certs/$3.key" |
    kubectl apply --server-side --field-manager=ztap-otel-example -f -
}
kubectl create namespace ztap-telemetry --dry-run=client -o yaml | kubectl apply -f -
put_secret ztap-telemetry otel-collector-tls server
put_secret ztap-system ztap-otel-client client
kubectl apply -f "$here/backend.yaml"
kubectl apply -f - <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: collector-dns
  namespace: ztap-telemetry
spec:
  podSelector: {matchLabels: {app: ztap-otel-collector}}
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock: {cidr: $dns_ip/32}
        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
          podSelector: {matchLabels: {k8s-app: kube-dns}}
      ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}]
YAML
kubectl -n ztap-telemetry rollout status deployment/loki --timeout=180s
kubectl -n ztap-telemetry rollout status deployment/otel-collector --timeout=180s
