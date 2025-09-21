# Strongswan VPN Server on Ubuntu 24.04 using XFRM Interface (instead of VTI/pure policy based)
- PSK based (doesn't work with Strongswan Android Client)
- EAP with Passwords
- EAP with certificates


# Common Steps
- disable password login:
  - change `/etc/ssh/sshd_config`
  - `rm /etc/ssh/sshd_config.d/50-cloud-init.conf`
  - `systemctl restart ssh`

- install strongswan:
  ```apt install strongswan strongswan-pki libcharon-extra-plugins libstrongswan-standard-plugins libstrongswan-extra-plugins```

## set up interface (don't do this, will not survive reboot)
- set up xfrm interface: persistent via a systemd unit or /etc/rc.local
```
ip link add xfrm0 type xfrm dev eth0 if_id 42
ip addr add 10.8.56.1/24 dev xfrm0
ip link set xfrm0 up
```

## alternate (do this) set up interface via systemd unit (will survive reboot)
Assuming eth0 is the uderlying device:
- edit `/etc/systemd/system/xfrm0.service`:
```
# /etc/systemd/system/xfrm0.service
[Unit]
Description=Create and configure xfrm0 for IPsec
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

# Safe cleanup (needs a shell for redirection/||)
ExecStartPre=/bin/sh -c '/usr/sbin/ip link del xfrm0 2>/dev/null || true'

# Create XFRM netdev bound to your underlay (change eth0 if needed)
ExecStart=/usr/sbin/ip link add xfrm0 type xfrm dev eth0 if_id 42

# Give it an address (adjust if you prefer another)
ExecStart=/usr/sbin/ip addr add 169.254.100.1/24 dev xfrm0

# Optional: slightly smaller MTU to avoid fragmentation through NATs
ExecStart=/usr/sbin/ip link set xfrm0 mtu 1400

# Bring it up
ExecStart=/usr/sbin/ip link set xfrm0 up

# On stop, remove it
ExecStop=/usr/sbin/ip link del xfrm0

[Install]
WantedBy=multi-user.target
```

- enable and start:
```
sudo systemctl daemon-reload
sudo systemctl enable --now xfrm0.service
```

## Firewalling
- ufw commands:
```
ufw allow ssh
ufw allow in 500,4500/udp
ufw allow out 500,4500/udp
ufw allow in proto esp to <server ip>
ufw allow out proto esp from <server ip>
ufw enable
```

# Only for EAP (i.e. password/certificate based)
- setup CA: (10 years certificate lifetime)
  - `ipsec pki --gen --type rsa --size 4096 --outform pem > ca.key`
  - ```
    ipsec pki --self --ca --lifetime 3650 \
    --in ca.key --type rsa \
    --dn "CN=VPN CA" \
    --outform pem > ca.crt
    ```
- generate server key and certificate:
  - `ipsec pki --gen --type rsa --size 4096 --outform pem > server.key`
  - ```
    ipsec pki --pub --in server.key --type rsa | ipsec pki --issue --lifetime 3650     --cacert ca.crt --cakey ca.key     --dn "CN=<server ip>"     --san "<server ip>"     --flag serverAuth --flag ikeIntermediate     --outform pem > server.crt
    ```

- install certificates and key:
  ```
  install -o root -g root -m 600 server.key /etc/ipsec.d/private/
  install -o root -g root -m 644 server.crt /etc/ipsec.d/certs/
  install -o root -g root -m 644 ca.crt     /etc/ipsec.d/cacerts/
  ``` 

# EAP with Passwords
- edit `/etc/ipsec.conf`
```
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=replace           # kick older session if same user logs in again
conn rw
    auto=add
    keyexchange=ikev2

    # --- Server side (certificate auth) ---
    left=%any                   # listens on all addrs
    leftid=<server ip>          # e.g. aa.bb.cc.dd  (MUST match cert SAN)
    leftauth=pubkey
    leftcert=server.crt
    leftsubnet=0.0.0.0/0
    installpolicy=no            # we route via xfrm interface
    if_id_in=42
    if_id_out=42
    fragmentation=yes           # large IKE_AUTH with certs
    mobike=yes                  # Android moves networks a lot

    # --- Client side (Android) ---
    right=%any                  # multiple roadwarriors
    rightid=%any                # allow many usernames; secrets control who gets in
    rightauth=eap-mschapv2
    eap_identity=%identity
    rightsourceip=10.100.0.0/24 # per-user virtual IPs
    rightdns=1.1.1.1,8.8.8.8    # hand out DNS (optional)
    rightsubnet=0.0.0.0/0       # tunnel all IPv4 from clients

    # --- Cryptographic hardening ---
    ike=aes256gcm16-prfsha256-ecp256,aes256-sha256-modp2048
    esp=aes256gcm16,aes256-sha256
    ike_lifetime=8h
    lifetime=1h
    rekeymargin=3m
    dpdaction=clear
    dpddelay=30s
    dpdtimeout=120s
```

- edit `ipsec.secrets`:
```
# This file holds shared secrets or RSA private keys for authentication.

# RSA private key for this host, authenticating it to any other host
# which knows the public part.
# you may also skip assigning explicit ip addresses
# they will be chosen from the pool given
: RSA server.key
<username> : EAP "<password>" : <ip1> # e.g. 10.100.0.10
<username2> : EAP "<password2>" : <ip2> # e.g. 10.100.0.11
```

- Android Client .sswan template file:
```
{
  "uuid": "1b2f3a4c-5678-90ab-cdef-112233445566",
  "name": "VPN Roadwarrior",
  "type": "ikev2-eap",
  "remote": {
    "addr": "<server ip>",
    "id": "<server ip>"
  },
  "local": {
    "id": "<username>"
  },
  "auth": {
    "method": "eap-mschapv2",
    "eap_id": "<username>",
    "password": "<password>"
  },
  "child": {
    "local_ts": ["0.0.0.0/0"],
    "remote_ts": ["0.0.0.0/0"]
  },
  "ike": {
    "integrity": ["sha256"],
    "encryption": ["aes256"],
    "dhgroup": ["modp2048"]
  },
  "esp": {
    "integrity": ["sha256"],
    "encryption": ["aes256"]
  },
  "dpd": 30
}
```

- transfer `ca.crt` from server and .sswan file to android client

- ToDo: Setup Firewall on Server:
  ```
  # Example: allow your LAN behind the server
  sudo ip route add 10.10.0.0/16 dev xfrm0
  # (optional) NAT client internet egress via server’s WAN:
  # pick your WAN interface (e.g. eth0)
  sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.100.0.0/24 -j MASQUERADE
  # allow IKE/ESP from the internet
  sudo iptables -A INPUT -p udp --dport 500  -j ACCEPT
  sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
  ```
- ToDo: Add xfrm interface setup at boot (via unit file or rc.local)


# EAP with Client Certificates
- create directories for client certificates
  - `mkdir pki`
  - `mkdir pki/certs`
  - `mkdir pki/private`
 
- generate per-user private key: 
```ipsec pki --gen --type rsa --size 3072 --outform pem > ~/pki/private/vpnuser.key```

- generate per-user certificate (10 years lifetime, clientAuth flag is important (else Strongswan Client won't present the certificate to the server!))
```
 ipsec pki --pub --in ~/pki/private/vpnuser.key --type rsa | ipsec pki --issue --lifetime 3650   --cacert ~/ca.crt --cakey ~/ca.key   --dn "CN=vpnuser" --san "vpnuser"  --flag clientAuth --outform pem > ~/pki/certs/vpnuser.crt
```

- export per-user certificate to .p12 format (for import into Strongswan client app), you will be prompted for a password. Remember it, you'll need it for importing the certificate into the Android app. `-legacy` option required for OpenSSL > v3 (else Android will error out upon import with "wrong password" message)
```
openssl pkcs12 -export -inkey ~/pki/private/vpnuser.key -in ~/pki/certs/vpnuser.crt \
  -certfile ~/ca.crt -name "vpnuser" -out ~/pki/vpnuser.p12 -legacy
```
- transfer ca.crt, .p12 to client
- import p12 on client (tap to import (not into WiFi!), enter password and descriptive name)
- import ca.crt on client

- Client config file:
```
{
  "uuid": "3d8f4f88-2c92-4d32-9f91-0b55a9eac101",
  "name": "Company VPN",
  "type": "ikev2-eap",
  "remote": {
    "addr": "<server ip>",
    "id": "<server ip>"
  },
  "local": {
    "id": "vpnuser"
  },
  "auth": {
    "method": "eap-tls",
    "client_cert_alias": "vpnuser"
  },
  "child": {
    "local_ts": ["0.0.0.0/0"],
    "remote_ts": ["0.0.0.0/0"]
  },
  "ike": {
    "encryption": ["aes256"],
    "integrity": ["sha256"],
    "dhgroup": ["modp2048"]
  },
  "esp": {
    "encryption": ["aes256"],
    "integrity": ["sha256"]
  },
  "dpd": 30
}
```

# Pre-Shared Key
Strongswan Android client doesn't support PSK. We need to choose EAP or something else.
From: https://docs.strongswan.org/docs/latest/os/androidVpnClient.html:
```
PSK authentication is not supported, as it is potentially very dangerous because the client might send the hash of a weak password to a rogue VPN server. Thus we prefer EAP authentication where the server is first authenticated by an X.509 certificate and only afterwards the client uses its password.
```

- edit `/etc/ipsec.conf`
```
config setup
    charondebug="ike 1, knl 1, cfg 0"

conn roadwarrior
    auto=add
    keyexchange=ikev2
    ike=aes256-sha256-modp2048
    esp=aes256-sha256

    # Server
    left=<server public ip>
    leftid=@server
    leftsubnet=0.0.0.0/0
    installpolicy=no
    if_id_in=42
    if_id_out=42

    # Clients
    right=%any
    rightid=%any
    rightsubnet=0.0.0.0/0

    authby=psk
```
- set up secrets per user: edit `/etc/ipsec.secrets`
```
@server @alice : PSK "AliceSecret"
@server @bob   : PSK "BobSecret"
```

- sysctl:
```
sudo tee -a /etc/sysctl.conf >/dev/null <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.xfrm0.rp_filter=0
EOF
sudo sysctl -p
```

- restart strongswan: `systemctl restart strongswan-starter`

- just in case: allow ufw OpenSSH in: `ufw allow OpenSSH` (even if it still is disabled so you won't lock yourself out if you enable later on)


## Android Client:
Strongswan Client doesn't accept PSK authentication.
Does it work with regular Android?
