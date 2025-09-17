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
