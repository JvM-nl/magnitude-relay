# Behind nginx

The relay listens on `127.0.0.1:7777` by default, so an nginx upstream that pointed at
strfry keeps working unchanged. On the same machine a Unix socket is cheaper: neither
side goes through the TCP stack for every message.

In the relay's settings:

```toml
[relay]
unix_socket = "/run/relay/relay.sock"   # the directory must exist
unix_socket_mode = "660"                # owner and group only...
real_ip_header = "x-real-ip"            # ...and nginx names each client
```

Put nginx's user in the relay's group (or leave the mode at `"666"`, as open as
127.0.0.1 already is). Then in the server block:

```nginx
location / {
    proxy_pass http://unix:/run/relay/relay.sock;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
}
```

`location /` also carries NIP-11 (`Accept: application/nostr+json`) and the private
`/peer/<secret>` paths of trusted peers: with `real_ip_header` set, a peer is matched
on the address nginx reports, so nginx must be the only way in (keep `bind` on
127.0.0.1).
