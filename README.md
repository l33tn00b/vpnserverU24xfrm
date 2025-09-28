# Strongswan VPN Server on Ubuntu 24.04 using XFRM Interface (instead of VTI/pure policy based) for Roadwarriors (Android Strongswan Client)
- PSK based (doesn't work with Strongswan Android Client)
- EAP with Passwords
- EAP with certificates
- Clients will be assigned IPs in 10.100.0.0/24 subnet
- We'll assign an interface ID for in- and ourgoing traffic (42 = 0x2A)
- IPv4-based (since the xfrm interface doesn't get an ip, no problems with IPv6 (enable forwarding, assign IPv6 addresses to clients))
- `eth0` is our outgoing device

# Common Steps
- disable password login:
  - change `/etc/ssh/sshd_config`
  - `rm /etc/ssh/sshd_config.d/50-cloud-init.conf`
  - `systemctl restart ssh`

- enable unattended upgrades
  
- for traditional `ipsec.conf` install strongswan like this:
  ```apt install strongswan strongswan-pki libcharon-extra-plugins libstrongswan-standard-plugins libstrongswan-extra-plugins```

- for modern `swanctl.conf` install strongswan like this:
  ```apt install charon-systemd libstrongswan-extra-plugins libcharon-extra-plugins```

- enable kernel IP forwarding:
  -  write drop-in config file: `echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ipforward.conf`
  -  reload config: `sysctl --system`
  
## Set Up Interface and Routing (don't do this, will not survive reboot)
- set up xfrm interface: persistent via a systemd unit or /etc/rc.local
  ```
  ip link add xfrm0 type xfrm dev eth0 if_id 42
  ip link set xfrm0 up
  ```
- routing
  ```
  ip route add 10.100.0.0/24 dev xfrm0
  ```

## Alternate (do this) set up interface via systemd unit (will survive reboot)
Assuming eth0 is the uderlying device:
- edit `/etc/systemd/system/xfrm0.service`:
  ```
  # /etc/systemd/system/xfrm0.service
  [Unit]
  Description=Create xfrm0 interface for IPsec
  After=network-pre.target
  Before=network-online.target
  Wants=network-online.target
  
  [Service]
  Type=oneshot
  ExecStart=/sbin/ip link add xfrm0 type xfrm if_id 42
  # set mtu (so we may later add a firewall rule for MSS clamping)
  ExecStart=/sbin/ip link set xfrm0 mtu 1400 up
  ExecStart=/sbin/ip route replace 10.100.0.0/24 dev xfrm0
  RemainAfterExit=yes
  
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
  ufw enable
  ```
- add masquerading for outgoing traffic: `nano /etc/ufw/before.rules`
  At the very top of the file, just after the header comments, insert a *nat table with POSTROUTING masquerade rules:
  ```
  *nat
  :POSTROUTING ACCEPT [0:0]
  
  # Masquerade all traffic going out the tunnel interface
  -A POSTROUTING -s 10.100.0.0/24 -o eth0 -j MASQUERADE
  
  COMMIT
  ```

- accept traffic from xfrm0. Edit `/etc/ufw/before.rules` and add to the filter `*filter` section (near other ufw-before-input rules):
  ```
  # allow in/out on xfrm0
  -A ufw-before-input -i xfrm0 -j ACCEPT
  -A ufw-before-output -o xfrm0 -j ACCEPT
  -A ufw-before-forward -i xfrm0 -j ACCEPT
  -A ufw-before-forward -o xfrm0 -j ACCEPT
  ```
- In `/etc/ufw/before.rules`, inside the `*filter` section before `COMMIT`, add:
  ```
  # allow traffic from VPN clients out to WAN
  -A ufw-before-forward -i xfrm0 -o eth0 -j ACCEPT
  # allow established/related back in
  -A ufw-before-forward -i eth0 -o xfrm0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ``` 

- reload ufw: `ufw reload`


- The only thing that's missing now is routing back to our client network



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

# EAP with Client Certificates
## Server Config (New swanctl Syntax)

- put into `/etc/swanctl/swanctl.conf`:
  ```
  connections {
    rw-eap-tls {
      version = 2
      proposals = aes256gcm16-prfsha256-ecp256,aes256-sha256-modp2048
  
      local_addrs = <your server ip>
      local {
        id = <your server ip>
        auth = pubkey
        certs = server.crt
        #send_cert = always
      }
      remote {
        auth = eap-tls
        id = %any
        eap_id = %any
      }
  
      pools = rw_pool
      dpd_delay = 30s
  
      children {
        net {
          local_ts  = 0.0.0.0/0           # full tunnel
          remote_ts = 0.0.0.0/0
          if_id_in  = 42
          if_id_out = 42
          policies = yes                  # install policies
          start_action  = start           # establish at start
          esp_proposals = aes256gcm16,aes256-sha256
          dpd_action    = clear
        }
      }
    }
  }
  
  pools {
    rw_pool {
      addrs = 10.100.0.0/24                # client ip range
      dns   = 1.1.1.1,8.8.8.8              # tell clients to use these dns servers
    }
  }
  
  secrets {
    private {
      file = server.key
    }
  }
  
  # Include config snippets
  include conf.d/*.conf
  ```
- restart: `systemctl restart strongswan`
- check:
  - `systemctl status strongswan`
  - when client is connected: `ip xfrm policy` should show your if_id (42 = 0x2a)
    ```
    src 0.0.0.0/0 dst 0.0.0.0/0
        dir out priority 399999
        tmpl src <server ip> dst <client ip>
                proto esp spi 0x4fd46c3c reqid 1 mode tunnel
        if_id 0x2a
    src 0.0.0.0/0 dst 0.0.0.0/0
            dir fwd priority 399999
            tmpl src <client ip> dst <srv ip>
                    proto esp reqid 1 mode tunnel
            if_id 0x2a
    src 0.0.0.0/0 dst 0.0.0.0/0
            dir in priority 399999
            tmpl src <client ip> dst <server ip>
                    proto esp reqid 1 mode tunnel
            if_id 0x2a
    ```
- when client is connected `ip xfrm state` should show something along the lines of
  ```
  src <server ip> dst <client ip>
          proto esp spi 0xcd4c2fa7 reqid 1 mode tunnel
          replay-window 0 flag af-unspec
          aead rfc4106(gcm(aes)) 0xf80f7e704492825f85ff1c4e372177073c9dcecdeec71e22b49d3986d9977dff4606e964 128
          encap type espinudp sport 4500 dport 56569 addr 0.0.0.0
          lastused 2025-09-28 13:48:02
          anti-replay context: seq 0x0, oseq 0x9, bitmap 0x00000000
          if_id 0x2a
  src <client ip> dst <server ip>
          proto esp spi 0xc90c336b reqid 1 mode tunnel
          replay-window 32 flag af-unspec
          aead rfc4106(gcm(aes)) 0x22234d8f7786ae2e7d679a2699682581509d6d09920ea231d31dfab059e38b422e73fd1a 128
          encap type espinudp sport 56569 dport 4500 addr 0.0.0.0
          lastused 2025-09-28 13:48:02
          anti-replay context: seq 0xc, oseq 0x0, bitmap 0x00000fff
          if_id 0x2a
    ```


## Client Certificates and Config
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

- Client config file
  ```
  {
    "uuid": "3d8f4f88-2c92-4d32-9f91-0b55a9eac101",
    "name": "Company VPN (vpnuser)",
    "type": "ikev2-eap-tls",
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
- import on client
- choose previously imported client profile



# EAP with Passwords
WTF. only swanctl syntax supports interface ids / marks?

- apt install charon-systemd (will also install strongswan-swanctl)


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
