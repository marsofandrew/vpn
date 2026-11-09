# State v4 design

The `pr-1-reliability` tag marks the previous v3 runtime. V4 preserves every
profile/client identity, REALITY key, short ID, public port, quota, usage total
and accounting checkpoint. Migration is local and atomic under the existing
state lock; no running configuration is changed by loading state.

V4 adds `node` (`id`, `role`), a dictionary of `upstreams` keyed by stable name,
and `routing_policies` keyed by policy name. Profiles gain `route` (a policy
name) and `transport` (type plus transport-specific settings). A single legacy
upstream becomes `main_vpn`; its proxy profiles reference the `main_vpn` policy.
Direct profiles reference `direct`. Deprecated `outbound_mode` remains a CLI
compatibility field and is kept consistent with the assigned policy.

Upstreams separate address/port, VLESS authentication, transport and security.
This avoids sharing TCP/REALITY-specific fields with XHTTP/TLS. Transport settings
are validated per variant. Supported combinations are TCP/REALITY,
XHTTP/REALITY and XHTTP/TLS. TLS verification is mandatory for upstreams.
XHTTP profiles carry security settings separately; TLS server certificates are
explicit paths supplied by the operator. No certificates are generated or
deployed during migration.

Policies support explicit direct, upstream and block routes initially. Each
proxy policy selects an enabled upstream by stable ID; removing/disabling a
referenced upstream is rejected. Health-based policies are introduced in the
next tagged milestone. No proxy route falls back to direct automatically.

Unknown state versions, unsupported imported transports/security and unknown
route targets are rejected. Import must not silently translate an unsupported
route into freedom. Legacy CLI upstream set/show/clear addresses `main_vpn`.

Before saving a migrated state, retain the original v3 snapshot in a private
`.v3.bak` file. Ordinary `.bak` snapshots then follow the current schema. To
downgrade, stop quota polling and Xray and restore the matching v3 code,
state/config and Compose backup together; reconcile post-backup usage manually.
Never regenerate keys with init during migration. Explicit pending configuration
and deployment journal semantics from PR 1 continue to apply.

## CLI examples

```sh
python3 vpnctl.py upstream add ny-reality --link 'VLESS_LINK' --no-restart
python3 vpnctl.py upstream add ny-cdn --link 'XHTTP_TLS_LINK' --no-restart
python3 vpnctl.py upstream list
python3 vpnctl.py route set default --policy ny-reality --no-restart
python3 vpnctl.py restart
```

Each added upstream also gets a single-upstream policy of the same name.
Names `api`, `direct` and `block` are reserved. Removing or disabling an assigned
upstream is rejected. Existing upstream set/show/clear commands target `main_vpn`.

Add an XHTTP/REALITY entry without altering existing profiles:

```sh
python3 vpnctl.py profile add xhttp-reality --port 9443 --transport xhttp \
  --security reality --xhttp-mode stream-one --path /YOUR_PATH \
  --reality-target www.cloudflare.com:443 --client phone --no-restart
```

For XHTTP/TLS, provide `--tls-server-name`, `--certificate` and
`--certificate-key` pointing at files in the container. The default Compose file
mounts `./certificates` (or `XRAY_CERT_DIR`) at `/etc/xray/certificates`, read-only.
Keep that host directory mode 0700 and private keys mode 0600. Server certificates
must be valid for the configured hostname. No certificates are committed or
provisioned here. Modes auto/packet-up/stream-up/stream-one parse in pinned Xray;
that does not establish CDN compatibility. XHTTP/REALITY uses stream-one.

Local validation covers all supported inbound/outbound combinations with the
pinned Xray binary and round-trip VLESS link parsing. Syntax validation does not
prove authentication, network accessibility or CDN compatibility. Repeat the
isolated Docker runtime test before production rollout and follow RELIABILITY.md.
