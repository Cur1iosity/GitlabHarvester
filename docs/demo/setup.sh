# Sourced (not recorded) by demo.tape inside the recording container.
#
# Serves the Fake GitLab as https://gitlab.example.com with a certificate from
# a throwaway private CA, and trusts that CA the way a system with a corporate
# CA would (REQUESTS_CA_BUNDLE). The recorded command then needs no TLS flags,
# and certificate verification really happens.

echo '127.0.0.1 gitlab.example.com' >> /etc/hosts
mkdir -p /tmp/tls
/opt/fake/bin/python - <<'EOF'
import trustme

ca = trustme.CA(organization_name="GitlabHarvester demo CA")
cert = ca.issue_cert("gitlab.example.com")
ca.cert_pem.write_to_path("/tmp/tls/ca.pem")
cert.private_key_pem.write_to_path("/tmp/tls/key.pem")
cert.cert_chain_pems[0].write_to_path("/tmp/tls/cert.pem")
EOF

(cd /demo-app && /opt/fake/bin/python -m fakegitlab --host 127.0.0.1 --port 443 \
    --scenario /vhs/demo/demo.yaml --tls-cert /tmp/tls/cert.pem --tls-key /tmp/tls/key.pem \
    >/tmp/fake-gitlab.log 2>&1 &)

export REQUESTS_CA_BUNDLE=/tmp/tls/ca.pem
export GITLAB_TOKEN=dev-token
cd /tmp
printf 'password\napi_key\ntoken\n' > words.txt
PS1='$ '
sleep 1.5
clear
