# CDN and independent client fallbacks

The `pr-3-health-routing` tag is the rollback point before optional ECH support.
This milestone initially pinned Xray 26.3.27; the final official-image update
pins 26.10.31. It preserves the existing supported transport
shapes and keys, and adds optional TLS ECH settings and private subscription
exports. Existing REALITY links retain their identities and parameters.

## Separate NY paths

Keep the original direct REALITY inbound and hostname. Add a distinct XHTTP/TLS
inbound, origin certificate and CDN hostname. For example, after obtaining and
privately installing the certificate under the host certificates directory:

```sh
python3 vpnctl.py profile add ny-cdn --port 8443 --transport xhttp \
  --security tls --tls-server-name cdn.EXAMPLE_DOMAIN \
  --certificate /etc/xray/certificates/origin.pem \
  --certificate-key /etc/xray/certificates/origin-key.pem \
  --path /YOUR_RANDOM_PATH --host cdn.EXAMPLE_DOMAIN --xhttp-mode packet-up \
  --client phone --no-restart
```

Configure the CDN hostname and origin port, certificate-validated origin TLS
(for Cloudflare, Full strict), matching HTTP host/path, permitted request sizes
and timeout behavior. Serve only the intended XHTTP path; do not expose any
management API. `packet-up` is a starting configuration, not a claim that every
CDN supports it. Native validation is not a CDN test. Validate the actual CDN
and origin certificate chain before enabling this profile in production.

CDN TLS termination exposes the VLESS stream to the CDN. Transport TLS is not
end-to-end confidentiality through that CDN. ECH conceals the inner ClientHello
from suitable observers; it does not hide application data from a terminating
CDN. HTTPS inside the tunnel can provide a separate end-to-end encryption layer.

## Independent entries and private subscriptions

Each remote connection entry carries its own existing UUID and transport
parameters. Adding it does not alter a gateway or exit runtime, regenerate keys,
or depend on RU availability. Group entries by the local client label:

```sh
python3 vpnctl.py endpoint add ru-gateway --client phone --link 'EXISTING_RU_LINK'
python3 vpnctl.py endpoint add ny-direct --client phone --link 'EXISTING_NY_LINK'
python3 vpnctl.py endpoint add ny-cdn --client phone --link 'NY_CDN_LINK'
python3 vpnctl.py endpoint list
python3 vpnctl.py subscription phone --output data/subscriptions/phone.txt
```

The file is a standard base64 subscription of enabled local matching client
links plus explicitly registered remote entries. It is atomically written mode
0600; base64 is encoding, not encryption. Treat the file as credentials and
transfer it securely. The normal export log contains only its output path.
No subscription HTTP host is implemented. Do not publish these files through an
unauthenticated web directory. A future hosting layer needs authenticated access
or strong unguessable tokens and TLS. Client applications must select/reconnect
between entries; server failover does not migrate an established client TCP
session. Quotas remain per node/profile, not centrally synchronized across nodes.

## Optional ECH

ECH is off by default and only supported with TLS. Pinned 26.10.31 uses native
`echConfigList` and `echServerKeys`; the old 25.3.6 runtime did
not implement these fields. Do not override the image with an older version and
assume it enforces ECH. Share links use the optional percent-encoded `ech`
parameter. A client must support that parameter and the pinned native feature.
Verify the client rather than assuming every subscription consumer supports ECH.

Client `ech_config_list` accepts standard Base64 ECHConfigList or HTTPS DNS
discovery, optionally `lookup.example+https://resolver/dns-query`. Query policy
remains full in the state contract; weaker query settings and arbitrary socket options are
rejected. Empty ECH means ECH is disabled. No fixed CDN edge IP is embedded.
Discovery requires a reachable resolver and valid HTTPS configuration; test it
from the target network. Resolver/bootstrap connectivity is separate from user
traffic carried by the tunnel.

For an ECH-terminating origin, generate keys privately using the pinned
`xray tls ech --serverName OUTER_NAME`, store the public config and secret server
bundle in separate files, and add `--ech-server-keys-file PATH` plus
`--ech-config-list-file PATH` when creating the TLS profile. The configured
tls-server-name remains the certificate/inner service name. A CDN that terminates
TLS supplies its own ECH configuration; origin keys are not a substitute for
the CDN's advertised client-facing ECH settings. Keep a separate non-ECH entry
for explicit fallback and test failure behavior before rollout.

Exact pinned field definitions and URI convention:
[Xray TLS builder](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/transport_security.go),
[ECH implementation](https://github.com/XTLS/Xray-core/blob/v26.10.31/transport/internet/tls/ech.go),
[share-link proposal](https://github.com/XTLS/Xray-core/discussions/716).

## Validation and rollback

Unit checks cover subscription grouping/permissions, transport round trips,
optional ECH parsing/rendering, rejected insecure/unsupported configurations and
preserved identity. Native and isolated runtime checks are repeated on the new
pin. Local Docker ECH tests passed an intact 128 KiB transfer with certificate
verification, verified plain-TLS fallback, and rejection of mismatched ECH config
and missing server keys without reaching the destination fixture. These tests
use the alternate image containing the pinned binary; the default remains GHCR.
Actual CDN compatibility, ECH DNS discovery on Russian networks, and
regional fixed/mobile accessibility remain operator validation. Test Saint
Petersburg, Moscow and Berezniki independently; whitelist-only mobile restrictions
may make every entry unavailable.

Back up state, certificates, keys, configuration and Compose overrides before
production changes. Deploy NY first, verify old direct clients, then RU, direct
NY and CDN, deliberately fail one path, restore it and verify cooldown. No such
deployment runs during development. Before downgrading to the PR 3 tag, remove
ECH-enabled definitions or restore matching pre-milestone state/config and image
together. Keep post-backup usage for reconciliation; never init over existing
state. Plain TLS and REALITY entries remain the fallback when ECH is unavailable.
