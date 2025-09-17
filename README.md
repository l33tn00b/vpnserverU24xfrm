# vpnserverU24xfrm
VPN Server on Ubuntu 24.04 with xfrm

- disable password login:
  - change `/etc/ssh/sshd_config`
  - `rm /etc/ssh/sshd_config.d/50-cloud-init.conf`
  - `systemctl restart ssh`

- install strongswan:
  ```apt install strongswan strongswan-pki```

- set up xfrm interface: persistent via a systemd unit or /etc/rc.local
```
ip link add xfrm0 type xfrm dev eth0 if_id 42
ip addr add 10.8.56.1/24 dev xfrm0
ip link set xfrm0 up
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


# Android Client:
strongswan .sswan config file:
```
{
  "uuid": "b7fbc1f1-1b29-4f9a-9c9e-abcdef123456",
  "name": "VPN to My Server",
  "type": "ikev2",
  "remote": {
    "addr": "<server public ip>",
    "id": "@server"
  },
  "local": {
    "id": "@alice"
  },
  "auth": {
    "method": "psk",
    "psk": "AliceSecret"
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
