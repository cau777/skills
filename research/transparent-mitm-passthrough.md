Research for [cau777/jetty-vm#3](https://github.com/cau777/jetty-vm/issues/3) — "Transparent MITM + selective passthrough implementation survey"

**Date:** 2026-08-15
**Method:** Primary-source only. mitmproxy, `inetaf/tcpproxy`, and `sniproxy` were cloned at `--depth 1` and read directly (paths below are relative to each repo root). nginx/HAProxy/iptables/nftables/Linux-kernel claims are quoted from official docs, man pages, and the actual kernel source file, fetched or read locally. Every claim below is followed by its source.

---

## 1. Does mitmproxy natively support "peek SNI, then either byte-level passthrough OR full MITM, per connection, with zero CA trust needed for the passthrough case"?

**Short answer: yes, precisely and by design.** mitmproxy parses the raw TLS ClientHello bytes to get the SNI, decides ignore-vs-intercept *before* ever touching the TLS state machine, and for ignored connections never performs a TLS handshake with the client at all — it replays the exact bytes it peeked into a byte-relay layer. No client-side crypto, no leaf-cert generation, no CA trust required for passthrough connections.

### 1.1 The mechanism, from source

mitmproxy's proxy core is a stack of "layers." Two independent code paths can make the ignore-vs-intercept decision, and both were read directly:

**(a) The `next_layer` addon (`mitmproxy/addons/next_layer.py`)** — this runs before any TLS layer is even selected. Its `_ignore_connection()` method (lines 198–263) builds a list of candidate hostnames from `context.server.peername`, `context.server.address`, an HTTP `Host:` header parsed with a plain regex (`_get_host_header`, lines 265–297), and — critically — a TLS ClientHello parsed straight out of the raw client bytes with `parse_client_hello(data_client)` (`_get_client_hello`, lines 299–344, called at line 235). This parse is a pure ClientHello-record parse, not a TLS handshake. If `ignore_hosts`/`allow_hosts` matches, `_next_layer()` (line 127) returns a `layers.TCPLayer(context, ignore=...)` instead of the `ServerTLSLayer`/`ClientTLSLayer` pair it would otherwise install (lines 126–153). Since the TLS layer is simply never instantiated for the connection, mitmproxy performs no TLS operation with the client whatsoever.

**(b) The `tls_clienthello` addon hook, inside the TLS layer itself (`mitmproxy/proxy/layers/tls.py`, `receive_handshake_data`, lines 562–625)** — even if a `ClientTLSLayer`/`ClientHelloLayer` *has* been installed, mitmproxy still doesn't jump straight to a handshake. It buffers incoming bytes into `self.recv_buffer` (line 567), parses them with `parse_client_hello()`/`dtls_parse_client_hello()` (lines 570–572) — again, a record parse, not a handshake — sets `self.conn.sni = client_hello.sni` (line 581), and fires:
  ```python
  tls_clienthello = ClientHelloData(self.context, client_hello)
  yield TlsClienthelloHook(tls_clienthello)
  ```
  (lines 583–584). `ClientHelloData` (`mitmproxy/tls.py`, lines 113–131) exposes `.client_hello` (with `.sni`, `.alpn_protocols`, etc. — `mitmproxy/tls.py` lines ~40–110) and a mutable `ignore_connection: bool = False` field an addon can set. **If an addon sets `ignore_connection = True`** (`tls.py` line 586 checks `tls_clienthello.ignore_connection`):
  ```python
  self.conn = self.tunnel_connection = connection.Client(peername=("ignore-conn", 0), sockname=("ignore-conn", 0))
  ...
  self.child_layer = tcp.TCPLayer(self.context, ignore=True)
  yield from self.event_to_child(events.DataReceived(self.context.client, bytes(self.recv_buffer)))
  ```
  (lines 586–605). `start_tls()` — the call that would perform the actual OpenSSL handshake and generate/serve a leaf certificate — is **never called** on this path (it's only reached at line 619, after the `if tls_clienthello.ignore_connection:` branch has already `return`ed at line 605). Instead the exact buffered ClientHello bytes are handed unmodified to a plain `TCPLayer`.

The `TlsClienthelloHook` class itself is declared right above, `mitmproxy/proxy/layers/tls.py` lines 171–177:
> "Mitmproxy has received a TLS ClientHello message. This hook decides whether a server connection is needed to negotiate TLS with the client (data.establish_server_tls_first)"

This corresponds to the documented `tls_clienthello` addon event ([docs.mitmproxy.org/stable/api/events.html](https://docs.mitmproxy.org/stable/api/events.html)):
```python
def tls_clienthello(data: mitmproxy.tls.ClientHelloData):
```
i.e. exactly the hook and field names (`data.client_hello.sni`, `data.ignore_connection`) needed to implement "peek SNI, decide Block/Allow/Inject, only Inject continues to cert generation."

**(c) `TCPLayer` is a byte relay, not a proxy with any TLS awareness** (`mitmproxy/proxy/layers/tcp.py`, `relay_messages`, lines 94–133): for each `DataReceived` event it does `yield commands.SendData(send_to, event.data)` bidirectionally, with `self.flow = None` when `ignore=True` was passed (constructor, lines 66–71), so it doesn't even build a flow object to log/replay — it is unconditional byte forwarding.

### 1.2 What `ignore_hosts`/`allow_hosts` mean, from the documented source (not summarized docs)

Read directly from `docs/src/content/howto/ignore-domains.md` (the actual markdown source rendered at [docs.mitmproxy.org/stable/howto/ignore-domains/](https://docs.mitmproxy.org/stable/howto/ignore-domains/)):

> "The `ignore_hosts` option allows you to specify a regex which is matched against a `host:port` string (e.g. "example.com:443") of a connection. Matching hosts are excluded from interception, and passed on unmodified."

and, on the SNI nuance specific to transparent mode:

> "In transparent mode, the ignore pattern is matched against the IP and ClientHello SNI host. While we usually infer the hostname from the Host header if the `ignore_hosts` option is set, we do not have access to this information before the SSL handshake. If the client uses SNI however, then we treat the SNI host as an ignore target."

`allow_hosts` is documented as "Opposite of `--ignore-hosts`" (same file's option table plus `mitmproxy/options.py`), and it's implemented in the same `_ignore_connection()` function (`next_layer.py` lines 245–252) as an allow-list inversion of the same logic — same SNI-peek mechanism, opposite polarity, appropriate for the ticket's "default-allow" model inverted for an explicit Inject allow-list, or vice versa for Block.

### 1.3 The crux question, answered plainly

**mitmproxy does genuine transparent TCP splicing with zero client-side crypto involvement for passthrough (ignored) connections.** It never negotiates any part of TLS with the client on that path — it parses the ClientHello as inert bytes, decides, and if ignoring, replays those exact bytes into a raw `TCPLayer`. No CA trust is needed in the VM for Allow/Block/unmatched traffic under either mechanism (`ignore_hosts`/`allow_hosts` via `next_layer.py`, or a custom addon setting `ignore_connection` in the `tls_clienthello` hook). CA trust is only exercised on the path that reaches `start_tls()` (`tls.py` line 619), i.e. only for connections mitmproxy actually decides to intercept.

One nuance worth flagging precisely: the relay is done in Python user space via `commands.SendData`/asyncio, i.e. it is **not** a kernel-level `splice(2)` zero-copy passthrough (contrast with §2's Go finding). It is still zero-TLS and zero-CA, just not zero-copy at the OS level.

### 1.4 Transparent mode / DNAT integration, from the doc source

`docs/src/content/howto/transparent-vms.md` (rendered at [docs.mitmproxy.org/stable/howto/transparent-vms/](https://docs.mitmproxy.org/stable/howto/transparent-vms/)) gives the exact iptables recipe for the "VM is its own gateway" case:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j REDIRECT --to-port 8080
```
then `mitmproxy --mode transparent`. This is the *client-configures-mitmproxy-as-gateway* scenario, which the ticket correctly identifies as different from our host-as-NAT-gateway scenario (see §3). Importantly, `docs/src/content/concepts/modes.md` (lines 371–380, "(b) Custom Routing") explicitly anticipates our exact case as a supported variant:

> "In some cases, you may need more fine-grained control of which traffic reaches the mitmproxy instance, and which doesn't. You may, for instance, choose only to divert traffic to some hosts into the transparent proxy."

— confirming that selectively redirecting only a subset of hosts (or, in our case, only a registered VM's traffic) into mitmproxy's transparent-mode listener is a documented, anticipated topology, not an unsupported hack. `--mode transparent` itself is documented (same file, lines 281–309):

> "In transparent mode, traffic is directed into a proxy at the network layer, without any client configuration required... when the packet arrives at the mitmproxy machine, it must still be addressed to the target server."

In our topology this means the DNAT/REDIRECT rule must be applied at the point closest to the VM (the bridge PREROUTING hook, §3), not translate the destination before mitmproxy sees it — consistent with mitmproxy's own requirement.

**Conclusion for §1:** mitmproxy's native mechanism is sufficient and precisely matches the ticket's requirement. It is not "awkward" — the `tls_clienthello` hook with `ignore_connection` is a first-class, purpose-built extension point for exactly this per-connection Allow/Inject branch, evaluated before any cert is generated.

---

## 2. Alternatives that SNI-sniff then splice-or-handoff

### 2.1 Go: `inetaf/tcpproxy` (github.com/inetaf/tcpproxy)

Cloned at commit dated 2026-04-07 ("HandleConn: propagate src IP via context") — **actively maintained** (< 5 months old relative to today, 2026-08-15), maintained under the `inetaf` (Tailscale-adjacent "Internet Engineering Task Force"-flavored networking) GitHub org, forked from Google's original `github.com/google/tcpproxy`.

**SNI peek, non-consuming** — `sni.go` lines 80–105, `clientHelloServerName(br *bufio.Reader)`:
```go
// clientHelloServerName returns the SNI server name inside the TLS ClientHello,
// without consuming any bytes from br.
func clientHelloServerName(br *bufio.Reader) (sni string) {
    ...
    hdr, err := br.Peek(recordHeaderLen)
    ...
    helloBytes, err := br.Peek(recordHeaderLen + recLen)
    ...
    tls.Server(sniSniffConn{r: bytes.NewReader(helloBytes)}, &tls.Config{
        GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
            sni = hello.ServerName
            return nil, nil
        },
    }).Handshake()
    return
}
```
It re-uses the Go stdlib TLS server handshake state machine purely as a ClientHello *parser* (feeding it a read-only, write-fails `sniSniffConn`) via `bufio.Reader.Peek`, which by definition does not advance the reader — this is the literal "peek without consuming" pattern the ticket asked about.

**Routing API** — `AddSNIRoute` / `AddSNIMatchRoute` / `AddSNIRouteFunc` (`sni.go` lines 26–53); `AddSNIRouteFunc`'s callback type is:
```go
type SNITargetFunc func(ctx context.Context, sniName string) (t Target, ok bool)
```
— i.e. a per-connection SNI-to-target decision function, suitable for a rule-table lookup (Block/Allow/Inject).

**True zero-copy splice for the passthrough case** — confirmed directly in `tcpproxy.go`, `proxyCopy` (lines 449–471):
```go
// Unwrap the src and dst from *Conn to *net.TCPConn so Go
// 1.11's splice optimization kicks in.
src = UnderlyingConn(src)
dst = UnderlyingConn(dst)

_, err := io.Copy(dst, src)
```
This is an explicit, commented acknowledgment that unwrapping to `*net.TCPConn` before calling `io.Copy` triggers Go's runtime `splice(2)`-based zero-copy fast path (Go's `net` package implements `io.ReaderFrom`/`io.WriterTo` for `TCPConn` using the Linux `splice` syscall since Go 1.11). Any already-peeked bytes are replayed first (`wc.Peeked`, lines 456–463) before the splice takes over — same cork/replay pattern as mitmproxy.

**Package doc confirms the "byte relay only" design** (`tcpproxy.go` lines 15–52):
> "Note that tcpproxy does not do any TLS encryption or decryption. It only (via DialProxy) copies bytes around. The SNI hostname in the TLS header is unencrypted, for better or worse."

**Handoff to a separate MITM engine**: `AddSNIRouteFunc`'s `Target` interface is generic — the "target" for an Inject-matched SNI can be `tcpproxy.To(mitmEngineAddr)` (a `DialProxy` dialing your embedded/local mitmproxy or your own `crypto/tls` MITM listener), while Allow-matched SNIs get `tcpproxy.To(realUpstream)` with the same `DialProxy`/`io.Copy`-splice machinery — i.e., exactly "peek once, then either splice raw or hand off to a decrypting engine," in one binary, using one library.

### 2.2 nginx `stream` + `ssl_preread`

**`ngx_stream_ssl_preread_module`** — official docs, [nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html):
> "The `ngx_stream_ssl_preread_module` module (1.11.5) allows extracting information from the ClientHello message ... **without terminating SSL/TLS**, for example, the server name requested through SNI or protocols advertised in ALPN."

The `$ssl_preread_server_name` variable is documented as: "server name requested through SNI." The "without terminating SSL/TLS" language is the primary-source confirmation that this is inspection-only, no handshake — the nginx-native analogue of mitmproxy's `next_layer`/`tls_clienthello` peek.

**Routing to passthrough vs. MITM backend** — `ngx_stream_core_module` ([nginx.org/en/docs/stream/ngx_stream_core_module.html](https://nginx.org/en/docs/stream/ngx_stream_core_module.html)), `proxy_pass` directive supports a variable as its target (since 1.11.3): `proxy_pass $upstream;`, where `$upstream` is normally computed with the `map` module keyed on `$ssl_preread_server_name`. A plain `proxy_pass` to a raw TCP backend performs unmodified byte relay with **no TLS termination by nginx** for that connection (nginx never touches the TLS bytes — it isn't a TLS endpoint on that path at all, since `listen ... ssl` was not used); a `proxy_pass` to a different backend that *does* terminate TLS (i.e., your MITM engine, e.g. mitmproxy listening in regular/reverse mode) is how the Inject case would be handed off. This is the standard, widely-documented "SNI-based TLS passthrough vs. termination split" nginx pattern — verified here from the `ssl_preread`/`proxy_pass`/variable-upstream primary docs, though I did not find nginx's own docs spelling out the split-routing recipe end-to-end on one page (the individual directive semantics above are each independently confirmed from nginx.org).

### 2.3 `sniproxy` (github.com/dlundquist/sniproxy)

**Status: deprecated.** From the repo's own `README.md` (cloned; last tag `0.7.0`, commit dated 2025-09-04):
> "Status: Deprecated — 2023-12-13 — When I started this project, there wasn't another proxy that filled this niche. Now, there are many proxies available to proxy layer-4 based on the TLS SNI extension, including Nginx. Additionally, web traffic is evolving: with HTTP/2, multiple hostnames can be multiplexed in a single TCP stream [preventing SNI Proxy] from routing it correctly based on hostname, and HTTP/3 (QUIC) uses UDP transport. SNI Proxy just doesn't support these protocols... For these reasons, I'm transitioning SNI Proxy to a deprecated status."

It still received a `0.7.0` tag roughly a year after the deprecation notice, so it isn't abandoned outright, but the maintainer explicitly discourages new adoption and states he'll only respond to "significant security or reliability" issues. Feature-wise it does exactly what the ticket describes for the pure-passthrough half ("Name-based proxying of HTTPS without decrypting traffic. No keys or certificates required," same README) but has **no built-in concept of handing a subset of connections to a MITM/decrypting engine** — it's SNI-route-only, so it would need to be paired with a separate tool for the Inject path, and its author's own deprecation notice (HTTP/2 multiplexing breaking SNI-based routing) is a real correctness risk for a security-sensitive gateway. **Recommendation: do not build on sniproxy.**

### 2.4 HAProxy `req.ssl_sni` + `send-proxy`

Quoted directly from `configuration.txt` fetched from `https://www.haproxy.org/download/3.0/doc/configuration.txt` (HAProxy 3.0 official configuration manual, section 7.3.6):

> "`req.ssl_sni` : string — Returns a string containing the value of the Server Name TLS extension sent by a client in a TLS stream passing through the request buffer if the buffer contains data that parse as a complete SSL (v3 or superior) client hello message. **Note that this only applies to raw contents found in the request buffer and not to contents deciphered via an SSL data layer, so this will not work with "bind" lines having the "ssl" option.**"

This is the exact confirmation the ticket asked for: `req.ssl_sni` operates on the *raw, undeciphered* ClientHello — it explicitly does not work on a `bind ... ssl` listener (i.e., a listener that terminates TLS), meaning routing decisions via `req.ssl_sni` are made with zero TLS engagement, before any handshake. The manual's own example (same section):
```
tcp-request inspect-delay 5s
tcp-request content accept if { req.ssl_hello_type 1 }
use_backend bk_allow if { req.ssl_sni -f allowed_sites }
default_backend bk_sorry_page
```
`tcp-request inspect-delay` (section 4, confirmed present in the manual at multiple example blocks) is the mechanism that buffers enough bytes to see the ClientHello before HAProxy commits to a backend — the HAProxy analogue of mitmproxy's buffering peek and nginx's `ssl_preread`.

Note the manual also documents `ssl_fc_sni` (contrasted in the same section) as the *post-decryption* SNI fetch ("This extracts... from an incoming connection made via an SSL/TLS transport layer and **locally deciphered by HAProxy**... This fetch is different from `req.ssl_sni` above in that it applies to the connection being deciphered by HAProxy and not to SSL contents being blindly forwarded") — i.e. HAProxy explicitly documents two different SNI fetches for the two different modes (raw passthrough vs. terminate), which is a clean primary-source confirmation that HAProxy natively supports both halves of the ticket's Allow/Inject split via `use_backend` routing rules on the same listener.

**`send-proxy`/`send-proxy-v2`** — same manual (section 5.2/5.3):
> "The `send-proxy` parameter enforces use of the PROXY protocol over any connection established to this server. The PROXY protocol informs the other end about the layer 3/4 addresses of the incoming connection, so that it can know the client's address or the public address it accessed to, whatever the upper layer protocol." `send-proxy-v2` is the same but "It also send[s] ALPN information if an alpn have been negotiated."

So: yes, PROXY protocol (v1 or v2, HAProxy's choice) is the standard way to hand the true client IP to a backend server (e.g. a MITM engine, or the raw upstream) when HAProxy is doing the connecting rather than the client dialing it directly. It is optional and only needed if the backend needs to see the original client IP rather than HAProxy's own.

**Fit for the ticket**: HAProxy can genuinely do "peek SNI raw, then route to a passthrough backend with zero TLS engagement, or to a decrypting backend" purely in its config language — no embedded scripting needed for the split decision itself (though the Inject-side credential injection would still need to happen in whatever backend HAProxy routes to, e.g. mitmproxy or a custom service). This makes HAProxy a legitimate alternative/front-end to a Go or Python MITM engine, but it does not replace the MITM engine itself — the actual cert generation / header injection still has to live in a Go/Python/Rust service behind it.

### 2.5 Summary table

| Tool | Peeks SNI without TLS engagement? | True kernel-level zero-copy splice for Allow case? | Built-in handoff to a separate MITM engine? | Maintenance |
|---|---|---|---|---|
| mitmproxy (`tls_clienthello`/`next_layer`) | Yes (source-confirmed, §1) | No — user-space relay via `SendData` | N/A — it *is* the MITM engine | Very active (commit 2 days before this research; version 13.0.0-dev) |
| `inetaf/tcpproxy` | Yes (`sni.go`, `bufio.Reader.Peek`) | Yes (`net.TCPConn`/`io.Copy` splice(2), source-confirmed) | Yes, via `Target`/`DialProxy` to any address | Active (commit ~4 months old as of 2026-08) |
| nginx `stream`+`ssl_preread` | Yes (docs-confirmed) | Yes, in principle (nginx event-loop I/O is efficient, though I did not verify nginx's own use of `splice(2)` from source in this pass) | Yes, via `proxy_pass $upstream` to a distinct backend | Very active (core nginx) |
| `sniproxy` | Yes (README-confirmed) | Not verified from source in this pass | No — SNI-route-only | **Deprecated** (maintainer notice) |
| HAProxy `req.ssl_sni` | Yes (manual-confirmed, distinguished from `ssl_fc_sni`) | Yes, in principle for `mode tcp` passthrough (not separately verified from source in this pass) | Yes, via `use_backend` to a distinct backend | Very active (core HAProxy) |

---

## 3. Host-side DNAT pattern for redirecting a VM's traffic (not the proxy's own)

### 3.1 `nat` table / `PREROUTING` semantics — from `man 8 iptables` (local man page)

> "nat: This table is consulted when a packet that creates a new connection is encountered. It consists of four built-ins: **PREROUTING (for altering packets as soon as they come in)**, INPUT (for altering packets destined for local sockets), OUTPUT (for altering locally-generated packets before routing), and POSTROUTING (for altering packets as they are about to go out)."

"As soon as they come in" is the primary-source confirmation that `nat`/`PREROUTING` fires before the kernel's routing decision — i.e. before the packet is classified as "for me" (→ `INPUT`/local delivery) vs. "not for me" (→ `FORWARD`/`POSTROUTING`/MASQUERADE). This is exactly why `REDIRECT` works: it rewrites the destination *before* that classification happens, so a packet that would otherwise have been forwarded (VM → internet, via the host acting as NAT gateway) is instead reclassified for local delivery to the app's listening socket.

### 3.2 `REDIRECT` vs `DNAT` — from `man 8 iptables-extensions` (local man page)

**`REDIRECT`:**
> "This target is only valid in the nat table, in the PREROUTING and OUTPUT chains, and user-defined chains which are only called from those chains. **It redirects the packet to the machine itself by changing the destination IP to the primary address of the incoming interface** (locally-generated packets are mapped to the localhost address, 127.0.0.1 for IPv4 ...). `--to-ports port[-port]` — This specifies a destination port or range of ports to use..."

**`DNAT`:**
> "This target is only valid in the nat table, in the PREROUTING and OUTPUT chains... It specifies that the destination address of the packet should be modified... `--to-destination [ipaddr[-ipaddr]][:port[-port[/baseport]]]` — which can specify a single new destination IP address..."

**Answer to the ticket's question ("REDIRECT vs full DNAT"):** since the proxy runs locally on the host and listens on the *same* host that owns `mpqemubr0`'s address, `REDIRECT --to-port <port>` is the correct, simpler target — it automatically rewrites the destination IP to "the primary address of the incoming interface" (i.e. the host's own `mpqemubr0` IP, whatever it is), so you don't need to hardcode the bridge IP. A full `DNAT --to-destination <host-ip>:<port>` would work identically in this specific case (proxy-on-host, listening on the bridge's own address) but is strictly more verbose/fragile (you'd have to hardcode or template the bridge IP) for zero additional benefit. Use `REDIRECT`.

Concretely, on the actual NAT gateway (the host), scoped to a single registered VM's source IP on the bridge interface:
```bash
iptables -t nat -A PREROUTING -i mpqemubr0 -s <vm-ip> -p tcp --dport 80  -j REDIRECT --to-port <port>
iptables -t nat -A PREROUTING -i mpqemubr0 -s <vm-ip> -p tcp --dport 443 -j REDIRECT --to-port <port>
```

### 3.3 `-i`/`-s` scoping — from `man 8 iptables`

> "`[!] -s, --source address[/mask][,...]` — Source specification. Address can be either a network name, a hostname, a network IP address (with /mask), or a plain IP address... The flag `--src` is an alias for this option."

> "`[!] -i, --in-interface name` — Name of an interface via which a packet was received (**only for packets entering the INPUT, FORWARD and PREROUTING chains**). ... If this option is omitted, any interface name will match."

This confirms both halves of the requirement: `-i mpqemubr0` scopes the rule to the bridge (so other interfaces/VLANs are untouched), and `-s <vm-ip>` further scopes it to one registered VM's source address — unregistered VMs on the same bridge, sharing the same `-i mpqemubr0`, simply don't match the rule and fall through untouched (default `ACCEPT`/no rule = ordinary MASQUERADE-based forwarding, unaffected).

### 3.4 `SO_ORIGINAL_DST` — from Linux kernel source (`net/netfilter/nf_conntrack_proto.c`, `torvalds/linux`, `master` branch, fetched raw via GitHub)

The `getorigdst()` function (lines 272–317) is the actual implementation:
```c
static int
getorigdst(struct sock *sk, int optval, void __user *user, int *len)
{
    ...
    tuple.src.u3.ip = inet->inet_rcv_saddr;
    tuple.src.u.tcp.port = inet->inet_sport;
    tuple.dst.u3.ip = inet->inet_daddr;
    tuple.dst.u.tcp.port = inet->inet_dport;
    ...
    h = nf_conntrack_find_get(sock_net(sk), &nf_ct_zone_dflt, &tuple);
    if (h) {
        struct sockaddr_in sin;
        struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
        sin.sin_family = AF_INET;
        sin.sin_port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
        sin.sin_addr.s_addr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
        ...
        copy_to_user(user, &sin, sizeof(sin));
        ...
    }
    return -ENOENT;
}

static struct nf_sockopt_ops so_getorigdst = {
    .pf         = PF_INET,
    .get_optmin = SO_ORIGINAL_DST,
    .get_optmax = SO_ORIGINAL_DST + 1,
    .get        = getorigdst,
    .owner      = THIS_MODULE,
};
```
This confirms the mechanism precisely: given the *already-redirected* socket's current (post-DNAT) `src`/`dst` tuple, it looks up the matching entry in the **generic connection-tracking table** (`nf_conntrack_find_get`) and returns `tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst` — the pre-NAT (original) destination IP:port — through the `SO_ORIGINAL_DST` getsockopt (registered for `PF_INET`; there's a parallel `ipv6_getorigdst`/`IP6T_SO_ORIGINAL_DST` at lines 328–379 for IPv6). This is the standard mechanism a userspace process on the accepting socket calls to recover "what destination did the client actually try to reach" after a `REDIRECT`/`DNAT` rewrote it — exactly what the proxy needs for the Allow (passthrough-to-real-destination) case, and as a fallback/cross-check alongside SNI for the Inject case.

Note this is Linux/netfilter-specific (there is no BSD/macOS equivalent of this getsockopt; other platforms have their own, different original-destination-recovery mechanisms not covered here since the ticket's target is a Linux host).

### 3.5 nftables equivalence

nftables wiki, "Performing Network Address Translation (NAT)" page:
> "By using redirect, packets will be forwarded to local machine. **Is a special case of DNAT where the destination is the current machine.**" ... "redirect only makes sense in prerouting and output chains of NAT type." Example: `nft add rule nat prerouting tcp dport 22 redirect to 2222`.

This confirms nftables' `redirect` statement is the direct semantic equivalent of iptables' `REDIRECT` target, in the same `prerouting` hook.

**On `SO_ORIGINAL_DST` with nftables specifically**: I could **not** find an nftables-wiki page that explicitly states "`SO_ORIGINAL_DST` works with nftables-created NAT rules" — this exact claim is not directly verified from an nftables-authored primary source. However, the kernel source read in §3.4 is decisive on the underlying mechanism: `getorigdst()` queries `nf_conntrack_find_get()` against the **generic conntrack table** (`nf_conntrack_find_get`, `nf_ct_tuplehash_to_ctrack`) — it contains no reference to `ip_tables`, `xt_*`, or any iptables-specific structure. Both the legacy iptables NAT targets and nftables' `nft`-based NAT statements are, architecturally, front-ends that program the *same* underlying `nf_nat`/`nf_conntrack` subsystem (this is why `iptables-nft` and `nft` can coexist and interoperate on one host at the packet-tracking level) — so a connection redirected via `nft ... redirect to <port>` populates the identical conntrack tuple structure that `getorigdst()` reads. I'm stating this as a well-grounded inference from the kernel source rather than a directly-quoted nftables claim, per the sourcing standard: **verified from kernel source that the mechanism is conntrack-based and NAT-front-end-agnostic; not separately confirmed from an nftables-authored doc.** Given how thin the risk surface is (either iptables-nft or nft can be used; both produce standard conntrack entries), this does not affect the design recommendation.

### 3.6 Putting §3 together

The design's premise — the host (real Multipass/QEMU NAT gateway for `mpqemubr0`) applies `nat`/`PREROUTING` `REDIRECT` rules scoped to one VM's source IP, on the bridge interface, redirecting only ports 80/443 to a local proxy port — is fully supported by ordinary Linux netfilter semantics, confirmed from `man 8 iptables`/`iptables-extensions` and the kernel's own `nf_conntrack_proto.c`. This is a **different, and simpler, scenario** than mitmproxy's own "Transparently Proxying VMs" walkthrough (§1.4), which configures the *guest* to use the proxy machine as its default gateway; here the host already *is* the gateway (confirmed true for this host per the ticket), so no guest-side routing change is needed at all — only host-side `PREROUTING` rules scoped per registered VM IP, which is exactly the "(b) Custom Routing" variant mitmproxy's own docs anticipate (§1.4).

---

## 4. Connection correlation / sequencing

Grounded in the mechanisms verified in §1–§3:

1. **Accept.** The proxy's listener `Accept()`s the TCP connection on its local port (this is the connection *after* `REDIRECT` rewrote the destination — the kernel completed the handshake with the VM as if the proxy's socket were the original destination; the VM is unaware anything changed).
2. **Recover true destination.** The proxy calls `getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, ...)` on the just-accepted fd (per §3.4, this is a plain `getsockopt` call any language's stdlib socket bindings can make — Go: `syscall.GetsockoptIPv6Mreq`-style raw `Getsockopt` via `unix.GetsockoptIPv6Mreq`/a manual `unix.Syscall`, commonly wrapped by third-party helper functions; Python: `socket.getsockopt(socket.SOL_IP, 80, 16)` where `80` is `SO_ORIGINAL_DST`'s numeric value on Linux, struct-unpacked as `sockaddr_in`). This gives the pre-DNAT destination IP:port — needed to know where to dial for the Allow case, and as a secondary signal alongside SNI.
3. **Peek the ClientHello without consuming it.** Buffer bytes off the socket into a small in-memory buffer (mitmproxy: `self.recv_buffer` accumulated across `receive_handshake_data` calls, `tls.py` line 567; `inetaf/tcpproxy`: `bufio.Reader.Peek(n)`, `sni.go` line 85/94, which per Go's `bufio` docs does not advance the reader) until a complete TLS record (or enough of one) is available, then parse it as a ClientHello structure only — never feed it into an actual TLS server handshake. Extract SNI. For plaintext HTTP, parse the first line + `Host:` header the same way (mitmproxy's `_get_host_header`, `next_layer.py` lines 265–297, is a concrete worked example: it regex-matches an HTTP request line and then a `Host:` header out of the still-unconsumed buffered bytes). **Then replay the exact peeked bytes** into whichever downstream path is chosen — mitmproxy does this via `event_to_child(events.DataReceived(..., bytes(self.recv_buffer)))` (`tls.py` line 601-603); `inetaf/tcpproxy` does it via its `Conn.Peeked []byte` field, drained first by `Conn.Read()` before falling through to the real socket (`tcpproxy.go` lines 250–279), and re-flushed explicitly in `proxyCopy` before the `io.Copy` splice takes over (`tcpproxy.go` lines 456–463). This buffer-then-replay ("cork/uncork") pattern is the concrete, source-verified answer to "peek without consuming."
4. **Rule-table lookup.** Look up the extracted SNI/Host against the priority-ordered Block/Allow/Inject rule table (this part is entirely application logic, not something any of the surveyed libraries prescribe — they only give you the SNI and a decision point).
5. **Branch:**
   - **Block** → close/reset the connection without forwarding anything (with mitmproxy: `commands.CloseConnection`; with a Go implementation: `conn.Close()` or write a TCP RST via `SetLinger(0)` then `Close()`).
   - **Allow** → dial the real destination — the IP:port recovered via `SO_ORIGINAL_DST` in step 2 (or the SNI-resolved IP if you prefer DNS-based resolution, though the ticket's requirement to keep npm/apt/curl working exactly as-is argues for using the conntrack-recovered original IP rather than re-resolving the hostname, to avoid any behavior change from DNS rebinding/round-robin) — then bidirectionally copy bytes with no further TLS awareness. In Go this is `inetaf/tcpproxy`'s `DialProxy`/`proxyCopy` path (§2.1), which gets you the `splice(2)` zero-copy fast path for free. In mitmproxy this is the `ignore_connection = True` / `ignore_hosts` path (§1), which is a user-space relay (not zero-copy) but is still zero-TLS/zero-CA.
   - **Inject** → look up the credential/rule for this SNI, then *now* (and only now) perform an actual TLS server handshake with the VM client using a leaf certificate signed by the app's CA for that SNI (Go: `tls.Config.GetCertificate` returning a freshly-minted/cached leaf per `ClientHelloInfo.ServerName`, confirmed from [pkg.go.dev/crypto/tls#Config](https://pkg.go.dev/crypto/tls#Config): "GetCertificate returns a Certificate based on the given ClientHelloInfo. It will only be called if the client supplies SNI information or if Certificates is empty."; mitmproxy: the default `start_tls()` path with its `tlsconfig` addon generating certs), dial upstream TLS to the real destination (recovered destination IP + SNI as the outbound `ServerName`), and decrypt/inject/re-encrypt.

**Named hooks/APIs for step 3's decision point, concretely:**
- mitmproxy: `tls_clienthello(data: mitmproxy.tls.ClientHelloData)` → `data.client_hello.sni`, set `data.ignore_connection = True`/`False` (§1.1(b)).
- `inetaf/tcpproxy`: `AddSNIRouteFunc(ipPort string, fn SNITargetFunc)` where `type SNITargetFunc func(ctx context.Context, sniName string) (t Target, ok bool)` (`sni.go` lines 46–53) — return a `Target` that is either `tcpproxy.To(realDest)` (Allow) or `tcpproxy.To(mitmEngineAddr)` (Inject).
- nginx: `$ssl_preread_server_name` consumed by `map` into `$upstream`, consumed by `proxy_pass $upstream;`.
- HAProxy: `req.ssl_sni` consumed by ACLs feeding `use_backend`.

---

## 5. Language/library fit

### Go: `crypto/tls` (`GetCertificate`) + `net.Dialer`/`io.Copy` splice + `inetaf/tcpproxy`

- **Maturity: very high.** `crypto/tls` is part of the Go standard library, released and versioned with the Go toolchain itself (no separate dependency/maintenance risk); `GetCertificate` has been stable stdlib API for many Go releases. The `splice(2)` optimization for `net.TCPConn`-to-`net.TCPConn` `io.Copy` is a *stdlib runtime* feature (landed Go 1.11, per the comment read directly in `inetaf/tcpproxy`'s source, §2.1) — meaning **true zero-copy passthrough for the Allow path is free and automatic**, not something you have to hand-roll with `splice(2)` syscalls yourself.
- `inetaf/tcpproxy` itself is a small (1,433 total lines across the package, per `wc -l`), focused, actively-maintained (§2.1) library that already implements exactly the "peek SNI → route by SNI → splice or handoff" pattern the ticket describes, with a documented, minimal API (`AddSNIRouteFunc`, `DialProxy`).
- **This combination is a mature, well-supported, and directly-applicable stack** for the whole architecture: `inetaf/tcpproxy` (or a thin custom equivalent using the same `bufio.Reader.Peek` pattern, since the library's core logic is ~115 lines in `sni.go`) for the sniff+route+splice half, plain `crypto/tls` (`tls.Config{GetCertificate: ...}`) for the Inject half's leaf-cert generation and client-side handshake, `crypto/tls` again (as a client, `tls.Dial`) for the upstream re-encryption leg, and `net.Dialer`/raw `net.Conn` for the Allow half's dial-and-splice. `SO_ORIGINAL_DST` is a raw `getsockopt` (via `golang.org/x/sys/unix`, itself an official, actively-maintained Go team package) — no third-party dependency needed for §3's recovery step either.

### Python: mitmproxy embedded as a library

- **Maturity: high, and it is the officially-sanctioned embedding path**, not an unofficial hack: `mitmproxy.tools.dump.DumpMaster` (`mitmproxy/tools/dump.py`, read directly, §1) is a plain Python class — `class DumpMaster(master.Master)` — constructed with an `Options` object and a list of addons; this is literally what the `mitmdump` CLI itself uses internally (`mitmproxy/tools/main.py` imports and constructs it). Any Python program can do the same: build an `Options`, add a custom addon implementing `tls_clienthello`/`next_layer`/an HTTP `request` hook for header injection, and run the `Master`'s asyncio loop itself.
- **Maintenance is excellent**: last commit read at clone time was 2026-08-13 (2 days before this research), on an in-development `13.0.0` version string (`mitmproxy/version.py`) — this is a fast-moving, well-resourced project. Recent changelog entries (`CHANGELOG.md`) show continuous feature work across mitmproxy, mitmweb, and a Rust component (`mitmproxy_rs`, "since mitmproxy 12" — used at least for WireGuard-mode and content-view internals per the changelog), so the project itself is a Python+Rust hybrid, not pure Python.
- **Trade-off vs. Go**: mitmproxy gives you the *entire* MITM engine (cert generation, HTTP parsing, header injection, flow logging) essentially for free and battle-tested — this is a large maturity advantage for the Inject half specifically. Its passthrough (Allow) half is zero-TLS/zero-CA (§1) but not zero-copy (user-space relay via asyncio `SendData`, §1.3) — a real but likely immaterial performance difference for this app's traffic volumes (a handful of dev VMs' npm/apt/curl traffic, not a high-throughput proxy fleet).

### Rust: rustls + DIY

- `rustls`'s `ResolvesServerCert` trait (confirmed from [docs.rs/rustls](https://docs.rs/rustls/latest/rustls/server/trait.ResolvesServerCert.html)) is the direct equivalent of Go's `GetCertificate` — `fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>>` — so the *cert-generation* primitive is equally mature in Rust.
- However, there is **no equivalent of `inetaf/tcpproxy`** — a single, small, actively-maintained, widely-adopted "SNI-sniff-then-route-or-splice" library — in the Rust ecosystem as far as this pass could determine. A web search (§2, not exhaustively verified against each crate's own docs/source in this pass) surfaced only smaller, narrower pieces: `tokio-splice`/`tokio-splice2` (raw `splice(2)` wrappers, narrow scope, smaller apparent user base than Go's stdlib-integrated splice), a separate `tcpproxy` crate (a different, unrelated project from the Go one of the same name), and assorted "TLS SNI/ALPN forwarding" side projects. Building this stack in Rust means composing `rustls` + `tokio` + one of these smaller splice crates + hand-rolled SNI-record parsing (or a TLS-parsing crate) yourself — materially more DIY/integration work than either the Go or Python option, with correspondingly less battle-testing of the composed whole. I did not find a single primary source establishing Rust as having a mature, "just import this" answer to the ticket's exact ask, the way Go and Python each do.

### Recommendation

**Go (`crypto/tls` + `inetaf/tcpproxy`-style SNI routing) and Python (mitmproxy embedded via `DumpMaster`) are both mature, defensible choices; Rust is comparatively immature/DIY for this specific composition and is not recommended as the primary implementation language for this ticket.** Between Go and Python: Go wins on the Allow-path performance/simplicity story (free kernel splice, one small dependency, one binary, easy to reason about for a security-sensitive network intercept) and on operational simplicity (single static binary, no Python/asyncio runtime to manage on the host); Python/mitmproxy wins on Inject-path maturity (a complete, actively-developed MITM+HTTP engine, with header-injection being a trivial mitmproxy addon `request` hook) at the cost of writing your own thin SNI-peek+splice front-end for the Allow path in front of it (which §1 shows mitmproxy already does natively via `ignore_hosts`/`tls_clienthello`, so this "cost" is actually near-zero — mitmproxy alone may be sufficient for the entire app, not just the Inject half).

---

## Bottom line

Use **mitmproxy, run in transparent mode as a single embedded process (`DumpMaster` + a custom addon), or a Go service built on `crypto/tls` + an `inetaf/tcpproxy`-style SNI-sniffing router**, as the two shortlisted architectures — both are primary-source-confirmed to do genuine, zero-CA, zero-TLS-handshake passthrough for Allow/Block/unmatched traffic (mitmproxy via `ignore_hosts`/the `tls_clienthello` hook's `ignore_connection` flag peeking the raw ClientHello before any cert is generated, §1; Go via `bufio.Reader.Peek` + `net.TCPConn` `io.Copy` kernel splice, §2.1) and full leaf-cert-based MITM only for Inject-matched SNIs. For interception, use host-side `iptables -t nat -A PREROUTING -i mpqemubr0 -s <vm-ip> -p tcp --dport {80,443} -j REDIRECT --to-port <port>` (confirmed correct chain/table/target semantics from `man 8 iptables`/`iptables-extensions`, §3), scoped per registered VM's source IP so unregistered VMs and non-web traffic are untouched, with the proxy recovering the true original destination via the Linux `SO_ORIGINAL_DST` getsockopt (confirmed from kernel source `net/netfilter/nf_conntrack_proto.c`, §3.4) for the Allow path's outbound dial. If a single language/runtime is preferred, **mitmproxy (Python) is likely sufficient end-to-end** given §1's findings that it natively implements both halves of this design as first-class, documented features rather than requiring a bolt-on; if operational simplicity of a static binary and free kernel-level splice throughput matter more, **Go is the mature alternative**, with Rust not recommended as a primary option due to the absence of an equivalently mature, all-in-one SNI-routing library.
