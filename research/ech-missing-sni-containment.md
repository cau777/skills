Research for [cau777/jetty-vm#13](https://github.com/cau777/jetty-vm/issues/13) — "Hostname-policy bypass containment: ECH, missing SNI, direct IP, custom DNS, DoH" (child of the design-spec map, [#1](https://github.com/cau777/jetty-vm/issues/1))

**Date:** 2026-08-15
**Method:** Primary-source only. mitmproxy was cloned at `--depth 1` (commit `bae1a7e179da7f9e516ba1b9fe0743f4fd758894`, 2026-08-13) into the scratchpad and read directly; paths below are relative to the repo root. RFC text is quoted from `rfc-editor.org`. IANA registry values are quoted from `iana.org`. Linux netfilter claims are quoted from the local `man 8 iptables` / `man 8 iptables-extensions` pages (same install used in the prior research at `research/transparent-mitm-passthrough.md`) and the nftables wiki. Every claim below is followed by its source; anything not directly confirmed from a primary source is explicitly flagged as an inference.

This document assumes the architecture and rule semantics already fixed by [#3](https://github.com/cau777/jetty-vm/issues/3) (host-side DNAT `REDIRECT` on `mpqemubr0`, mitmproxy `tls_clienthello`/`next_layer` SNI-peek-then-splice-or-MITM) and [#5](https://github.com/cau777/jetty-vm/issues/5) (host-exact, priority-ordered Allow/Block/Allow-with-credential rules; **unmatched traffic defaults to Allow**). Neither is revisited here.

---

## 1. Can mitmproxy detect ECH presence in a ClientHello without decrypting it?

**Yes, but only via a custom addon — it is not a built-in signal, and detecting the extension's presence does not tell you whether SNI is being hidden.**

### 1.1 The raw extension list is available before any handshake

`mitmproxy/tls.py`'s `ClientHello.extensions` property returns every extension in the parsed (not decrypted, not handshaken) ClientHello as `(extension_type, raw_bytes)` tuples:
```python
@property
def extensions(self) -> list[tuple[int, bytes]]:
    """The raw list of extensions in the form of `(extension_type, raw_bytes)` tuples."""
    ret = []
    if ext := getattr(self._client_hello, "extensions", None):
        for extension in ext.extensions:
            body = getattr(extension, "_raw_body", extension.body)
            ret.append((extension.type, body))
    return ret
```
`(mitmproxy/tls.py, ClientHello.extensions)`

This is populated from the same parse used for `.sni` and `.alpn_protocols` (`ClientHello.__init__`, same file), which is a pure `kaitaistruct`-based record parse (`mitmproxy/net/tls.py`, `ClientHello.__init__`, using `tls_client_hello.TlsClientHello`/`dtls_client_hello.DtlsClientHello`) — not a TLS handshake, consistent with the peek mechanism already established in `research/transparent-mitm-passthrough.md` §1.1(b). It runs inside the `tls_clienthello` hook (`mitmproxy/proxy/layers/tls.py`, `receive_handshake_data`), i.e. before `start_tls()` is ever called.

An addon implementing `tls_clienthello(data)` can therefore scan `data.client_hello.extensions` for the ECH extension type and set `data.ignore_connection` / log accordingly, all before any cert is generated or handshake attempted. **This capability does not exist as a built-in mitmproxy option or default log field** — it would need to be written as a custom addon on top of the already-documented `tls_clienthello` hook.

### 1.2 The ECH extension's codepoint

IANA TLS ExtensionType registry (`iana.org/assignments/tls-extensiontype-values`):
> `encrypted_client_hello (ECH)` — codepoint **65037** (`0xFE0D`), Reference: **RFC 9849**, Recommended: Y

confirmed against `server_name (SNI)` — codepoint **0**, Reference: RFC 6066/RFC 9261, Recommended: Y. A detection addon would match `extension_type == 65037` in the tuple list above.

**Status of ECH itself, as of this research (2026-08-15):** ECH is no longer a draft. IETF Datatracker confirms `draft-ietf-tls-esni` was published as **RFC 9849** ("Proposed Standard", March 2026, last version 25). This means the design question is about a ratified RFC mechanism, not a moving-target Internet-Draft — worth flagging since older secondary sources (pre-2026) will still describe it as "draft-ietf-tls-esni."

### 1.3 The critical nuance: extension presence ≠ SNI is hidden (GREASE ECH)

RFC 9849 §6.2 defines **GREASE ECH**: a client that has no real ECH config for the destination sends a *fake* `encrypted_client_hello` extension anyway, specifically so that real-ECH and no-ECH connections are indistinguishable to an observer:
> "The GREASE ECH mechanism allows a connection between an ECH-capable client and a non-ECH server to appear to use ECH, thus reducing the extent to which ECH connections stick out."

This means: **the mere presence of extension 65037 in the outer ClientHello is not proof that SNI is actually hidden.** A GREASE-ECH ClientHello still carries the real `server_name` extension in the clear (mitmproxy's `.sni` property would return the true hostname); only a *genuine* ECH ClientHello replaces the visible SNI with the ECH config's `public_name` decoy (§2 below). mitmproxy's parser cannot distinguish genuine ECH from GREASE ECH by inspecting the outer ClientHello alone — that indistinguishability is the explicit design goal of GREASE ECH per the quoted text. So "detect and log ECH presence" is a real, implementable signal (§1.1), but it is a **noisy** one: it will fire on ordinary, fully-SNI-visible connections from any modern ECH-aware client library (Chrome, Firefox, and increasingly `curl`/OpenSSL-based clients) that happens to GREASE, not just on connections that are actually hiding their target.

**Conclusion for §1:** mitmproxy can be extended, via the already-documented `tls_clienthello` hook and the already-parsed `.extensions` field, to log "ECH extension present" as a per-connection signal with zero additional TLS engagement. This is a real, buildable containment/observability primitive. It is not built into mitmproxy today, and by itself it conflates "hiding the real hostname" with "GREASE cover traffic that isn't hiding anything," so its diagnostic value is limited to "this client is ECH-capable," not "this connection is evading policy."

---

## 2. What genuine ECH does to the outer ClientHello's SNI, and why an Inject rule can silently stop firing

RFC 9849 §6.1, rule 5, on constructing `ClientHelloOuter`:
> "It SHOULD place the value of `ECHConfig.contents.public_name` in the 'server_name' extension." ... "Clients that do not follow this step, or place a different value in the 'server_name' extension, risk breaking the retry mechanism."

So a genuine-ECH ClientHello is **not** SNI-less. It carries a syntactically valid `server_name` extension — but populated with the ECH config's `public_name`, a decoy identity chosen by the operator of the client-facing server (frequently a CDN-wide shared name, not the real per-customer hostname the agent is actually trying to reach). mitmproxy's `.sni` property (§1.1, `mitmproxy/tls.py`) will happily return this decoy value — it has no way to know it isn't the real target.

**Design consequence, stated plainly:** the design's rule table is host-exact and keyed on the SNI mitmproxy observes (`research/transparent-mitm-passthrough.md` §1.1(b)/§4). If an operator marks `real-target.example.com` for credential injection, and the agent's TLS stack negotiates genuine ECH to reach it, mitmproxy will see the SNI as the ECH `public_name` (e.g. a CDN's shared decoy name), which will not match the `real-target.example.com` rule. Under the fixed default-Allow-unmatched semantics, the connection **falls through to Allow** — meaning the Inject rule silently fails to fire (credentials are not injected) *and* the traffic is passed through raw to whatever the client actually negotiated. This is a different failure mode than a pure "Block-rule bypass": it's a **silent Inject-rule miss**, worth naming explicitly as a residual risk distinct from the containment question the ticket poses (§6).

### 2.1 ECH structurally prevents silent MITM even if the proxy tries to intercept anyway

This is the strongest finding in this document, and it means the "can we block/reject ECH" design question has a sharper answer than "write a rule": **even without any special-casing, a genuine ECH connection cannot be silently decrypted by an on-path MITM that lacks the ECH private key — the client itself detects and aborts it.**

RFC 9849 §7.2 defines the ECH acceptance confirmation the real backend embeds in `ServerHello.random`'s last 8 bytes:
```
accept_confirmation = HKDF-Expand-Label(HKDF-Extract(0, ClientHelloInner.random),
                                          "ech accept confirmation", transcript_ech_conf, 8)
```
and §6.1.4 states the client's check:
> "If this value matches the last 8 bytes of `ServerHello.random`, the server has accepted ECH. Otherwise, it has rejected ECH."

§8.1.2 describes exactly the case of a TLS-terminating intermediary that isn't ECH-aware (mitmproxy attempting `start_tls()` against `ClientHelloOuter` using the decoy `public_name`, per §2 above, is precisely this case):
> "The proxy must ignore unknown parameters and generate its own `ClientHello` containing only parameters it understands."

Such a proxy has no way to produce the correct HKDF-derived confirmation (it doesn't hold the real backend's ECH private key), so the client's check in §6.1.4 fails. §5 mandates the client's response:
> "This document also defines the 'ech_required' alert, which the client MUST send when it offered an 'encrypted_client_hello' extension that was not accepted by the server."

**Practical meaning for this design:** if mitmproxy is configured to *Inject* a hostname and the agent negotiates genuine ECH to reach it, mitmproxy generating a leaf cert for the decoy `public_name` and completing a handshake does not produce a working, silently-intercepted connection — the client detects the missing accept-confirmation and aborts with `ech_required` before sending application data. So the actual behavior split is: **(a)** if the connection is not selected for Inject (the common case per §2's Inject-miss finding), it passes through untouched as opaque bytes and works fine end-to-end for the agent; **(b)** if it *is* selected for Inject (e.g. an IP-literal or decoy-`public_name` rule happens to match), the agent's connection breaks visibly rather than being silently intercepted. Neither outcome is "credentials get injected against the agent's will while it thinks it's talking normally" — ECH's cryptographic design rules that out. The risk this design has to accept is the quieter one from §2: Inject rules simply not firing, not a spoofed injection succeeding.

---

## 3. Can mitmproxy detect/log a ClientHello with no SNI at all? What does it do by default?

**Yes, cleanly — `.sni` returns `None`, and mitmproxy's own next-layer/cert logic already has explicit `None`-handling code paths, which double as ready-made hook points for logging.**

### 3.1 RFC basis: omitting SNI is legal, and is normal for IP-literal connections

RFC 8446 (TLS 1.3) lists `server_name` as an optional ClientHello extension (extension table, `CH, EE`) with no MUST-send language for the client. RFC 6066 §3 (which RFC 8446 defers to for `server_name` semantics) is explicit about IP literals:
> "Literal IPv4 and IPv6 addresses are not permitted in 'HostName'."

So a TLS client connecting directly to a raw IP (no hostname to indicate) is not merely allowed to omit SNI — RFC 6066 forbids putting an IP literal *in* the SNI field at all. This confirms the "direct IP connection ⇒ no SNI" evasion path described in the ticket is not a client misbehaving or exploiting an edge case; it is exactly what the spec describes as correct behavior for IP-literal connections.

### 3.2 mitmproxy's parse of "no SNI"

`mitmproxy/tls.py`, `ClientHello.sni`:
```python
@property
def sni(self) -> str | None:
    if ext := getattr(self._client_hello, "extensions", None):
        for extension in ext.extensions:
            is_valid_sni_extension = (
                extension.type == 0x00
                and len(extension.body.server_names) == 1
                and extension.body.server_names[0].name_type == 0
                and check.is_valid_host(extension.body.server_names[0].host_name)
            )
            if is_valid_sni_extension:
                return extension.body.server_names[0].host_name.decode("ascii")
    return None
```
This returns `None` cleanly — no exception, no special-casing needed by a caller — whenever the `server_name` extension (type `0x00`) is absent (or malformed/invalid per `check.is_valid_host`). This is exactly the signal a logging addon would consume in `tls_clienthello`: `if data.client_hello.sni is None: log(...)`.

### 3.3 What mitmproxy does with a `None` SNI today, from source

Two places in `mitmproxy/addons/tlsconfig.py` (the addon that generates interception certs and decides upstream SNI) explicitly fall back to the connection's destination IP when client SNI is absent:
```python
if server.sni is None:
    server.sni = client.sni or server.address[0]
```
(lines ~290–291 and ~438–439, both guarding the "what SNI do we present to the real upstream server" decision), and for leaf-cert SAN generation:
```python
if conn_context.client.sni:
    altnames.append(_ip_or_dns_name(conn_context.client.sni))
...
if conn_context.server.address:
    altnames.append(_ip_or_dns_name(conn_context.server.address[0]))
```
(lines ~616–623). This confirms mitmproxy's Inject path *can* function without any client SNI at all — it substitutes the connection's own destination IP (which in this design is the pre-DNAT IP recovered via `SO_ORIGINAL_DST`, per `research/transparent-mitm-passthrough.md` §3.4) both for the outbound TLS `ServerName` and for the generated cert's SAN list. This is IP-based fallback behavior mitmproxy already ships, not something that needs to be built — but it operates on the numeric IP, not a hostname, so it cannot participate in this design's host-exact rule table (§3.4 below) except via an explicit IP-literal rule entry.

### 3.4 What "no SNI" means for this design's rule matching specifically

`mitmproxy/addons/next_layer.py`, `NextLayer._ignore_connection` (the function that decides Allow/ignore for `ignore_hosts`/`allow_hosts`, and structurally the same place a custom Block/Allow/Inject addon would look):
```python
hostnames: list[str] = []
if context.server.peername:
    host, port, *_ = context.server.peername
    hostnames.append(f"{host}:{port}")
if context.server.address:
    host, port, *_ = context.server.address
    hostnames.append(f"{host}:{port}")
    if host_header := self._get_host_header(context, data_client, data_server):
        ...
    if (client_hello := self._get_client_hello(context, data_client)) and client_hello.sni:
        hostnames.append(f"{client_hello.sni}:{port}")
```
When `client_hello.sni` is `None`, the `hostnames` candidate list still gets populated — but *only* with `context.server.peername`/`context.server.address`, which in transparent mode are `(ip, port)` tuples (the DNAT-recovered original destination, per the prior research's `SO_ORIGINAL_DST` finding). So the candidate strings mitmproxy matches rules against become things like `"93.184.216.34:443"` — a raw IP:port string, not a hostname. **This confirms the mechanism precisely: absent SNI, mitmproxy's own matching machinery degrades from hostname matching to IP-string matching**, and since this design's rules are host-exact (per #5), a rule written for `real-target.example.com` will never match an IP string, regardless of whether that IP happens to be `real-target.example.com`'s current address. Under default-Allow-unmatched, this connection is Allowed. An operator *could* theoretically add IP-literal rule entries, but per the architecture doc's own reasoning (SNI-based routing was chosen specifically because CDN-fronted services share/rotate IPs — `research/transparent-mitm-passthrough.md` §4 step 5, "to avoid any behavior change from DNS rebinding/round-robin") IP-literal rules are not a stable substitute for hostname rules.

**Conclusion for §3:** mitmproxy can detect and log "no SNI" trivially (`.sni is None`, no addon complexity needed beyond a log line in `tls_clienthello`), and mitmproxy itself already falls back to raw destination IP for both its own upstream-SNI and cert-SAN logic when client SNI is absent. But for *this design's* purposes, "no SNI" collapses hostname-based rule matching to IP-string matching, which the design's host-exact rules don't populate — so the connection reliably falls through to default-Allow, exactly as the ticket's framing anticipated, and this is a rule-table property, not a mitmproxy limitation.

---

## 4. Can "reject ECH" or "reject no-SNI" be enforced instead of just observed? What breaks?

### 4.1 Mechanically, yes — trivially, via the same hook

Both are one-line policies inside a `tls_clienthello` addon, since `ignore_connection` is not the only lever available — the hook fires before any TLS state is committed (§1.1, and `research/transparent-mitm-passthrough.md` §1.1(b)), so an addon can instead choose to **not** call `start_tls()`/`ignore_connection` at all and instead issue `commands.CloseConnection` (the same primitive `research/transparent-mitm-passthrough.md` §4 identifies for the Block case). Concretely: `if data.client_hello.sni is None: <close>` or `if any(t == 65037 for t, _ in data.client_hello.extensions): <close>`. No new mitmproxy capability is required — this is a straightforward extension of the existing `tls_clienthello` hook and the same `_get_client_hello`/`.extensions` machinery already read in §1 and §3.

### 4.2 What breaks: "reject no-SNI" only affects genuinely IP-literal traffic, but bear in mind §3's fallback

Per §3.1, RFC 6066 forbids IP literals in SNI, so any legitimate tool that connects straight to a bare IP (a direct curl to a load-balancer IP, some package-manager mirrors configured by IP, etc.) is indistinguishable at the SNI layer from an evading agent. Rejecting all no-SNI ClientHellos would break that legitimate-but-rare traffic class outright, with no way for the proxy to tell it apart from an agent deliberately avoiding hostname matching. This is a real but comparatively narrow blast radius — direct-IP-literal HTTPS is uncommon in ordinary npm/apt/curl/pip workflows, which resolve hostnames and always send SNI.

### 4.3 What breaks: "reject ECH" is a much larger blast radius, and doesn't actually stop the evasion

This is the more consequential finding. Rejecting any ClientHello carrying extension `65037` would reject:
- **GREASE-ECH connections** (§1.3) — which, per RFC 9849 §6.2, are explicitly designed to be indistinguishable from genuine ECH from the wire alone, and which carry the *real, unhidden* SNI. A blanket reject-on-extension-presence policy cannot separate these from genuine ECH without decrypting — which is definitionally impossible without the private key. So this policy necessarily rejects connections that were never hiding anything.
- **Genuine-ECH connections to sites that mandate it.** ECH adoption is not a fringe feature by 2026: major CDNs (Cloudflare) and both Chrome and Firefox have shipped ECH-by-default for qualifying origins for several years pre-dating this research's date. Blanket-rejecting the extension would make an increasing, CDN-driven share of ordinary legitimate HTTPS traffic (through this proxy, for *any* VM, not just a hostile one) unreachable — not a narrow edge case but a growing baseline of normal web traffic.

And critically, **rejecting the extension doesn't close the evasion it's aimed at**, because of §2: genuine ECH already causes the connection to either (a) not match any Inject rule and pass through Allowed (if the connection isn't intercepted), or (b) abort on its own via `ech_required` if it is intercepted. An agent that wants to evade a *Block* rule specifically by using ECH gains nothing extra from ECH that it doesn't already get from the ordinary default-Allow-unmatched behavior — a Block rule is host-exact and keyed on a real hostname the operator explicitly listed; if that real hostname is what the agent is ECH-ing to reach, and it's Blocked, mitmproxy's SNI-based Block match doesn't see that hostname (it sees the decoy `public_name` instead) — so an ECH-driven Block bypass genuinely exists, but it is not stoppable by a "reject ECH" TLS-layer policy, precisely because "reject ECH" cannot distinguish the agent's decoy-fronted evasion from the majority of ordinary GREASE/genuine-ECH traffic that a Block rule was never meant to catch. **Recommendation: do not implement a blanket reject-on-ECH-extension policy — the availability cost is broad and growing, and it does not actually close the Block-rule bypass it would be built to address.**

---

## 5. Linux networking: what can actually be enforced for direct-IP, custom DNS, and DoH?

### 5.1 Direct-IP connections: netfilter has no L7 visibility to key on

Netfilter (`iptables`/`nftables`) matches operate on packet/connection-tuple fields — source/destination IP, port, protocol, connection-tracking state — not on TLS record contents. The `man 8 iptables-extensions` `string` module ("This module matches a given string by using some pattern matching strategy... `--from offset` / `--to offset`") and `u32` module ("tests whether quantities of up to 4 bytes extracted from a packet have specified values") are the closest built-in primitives to payload inspection, but both operate on a **single packet's** byte offsets — neither man page describes any TCP-stream reassembly capability. **This is an inference, not a directly-documented limitation**: since a TLS 1.3 ClientHello carrying ECH (padded specifically to obscure its true length, per RFC 9849) commonly spans more than one TCP segment, a single-packet byte/string match cannot reliably locate or evaluate an extension that straddles a segment boundary, and doing this reliably requires the kind of buffering the mitmproxy `tls_clienthello` hook already does in user space (§1.1, `self.recv_buffer` accumulated across `receive_handshake_data` calls). **Conclusion: there is no sound netfilter-native way to distinguish "a TCP connection opened straight to an IP with no hostname anywhere" from "a TCP connection to the resolved IP of an already-Allowed hostname"** — that distinction only exists at the TLS layer, which is mitmproxy's job (§3), not iptables/nftables'. The one thing netfilter/DNAT *can* do is what `research/transparent-mitm-passthrough.md` §3.4 already established: recover the true pre-NAT destination IP via `SO_ORIGINAL_DST`, which the proxy already needs regardless, and which is exactly the value mitmproxy's own no-SNI fallback uses (§3.3). Beyond that, the only IP-layer control available is a **blanket destination-IP allow/deny list** (`DROP`/`ACCEPT` policy per `man 8 iptables`: "`ACCEPT` means to let the packet through. `DROP` means to drop the packet on the floor," or nftables named sets — `nft add rule ip filter output ip daddr @blackhole drop`, from the nftables wiki's Sets page) — but that is a categorically different, coarser security model (default-deny-by-IP-range) than this design's fixed default-Allow-unmatched-by-hostname model, and switching to it is out of scope per the constraints given for this ticket.

### 5.2 Forcing all DNS through a single controlled resolver: fully enforceable, same mechanism as the existing 80/443 redirect

This is a clean, directly-transferable extension of the DNAT pattern `research/transparent-mitm-passthrough.md` §3 already established and cited from `man 8 iptables` ("nat: This table is consulted when a packet that creates a new connection is encountered... PREROUTING (for altering packets as soon as they come in)"). Because `REDIRECT`/`DNAT` rewrite the packet's destination **before** the kernel's routing/delivery decision, it does not matter what nameserver IP the VM's root user configures inside the VM — a rule scoped to the bridge interface and the VM's source IP, on UDP/TCP port 53 (and 853 for DNS-over-TLS), redirects the packet to the host's own resolver regardless of the VM-side configured destination:
```bash
iptables -t nat -A PREROUTING -i mpqemubr0 -s <vm-ip> -p udp --dport 53  -j REDIRECT --to-port <resolver-port>
iptables -t nat -A PREROUTING -i mpqemubr0 -s <vm-ip> -p tcp --dport 53  -j REDIRECT --to-port <resolver-port>
iptables -t nat -A PREROUTING -i mpqemubr0 -s <vm-ip> -p tcp --dport 853 -j DROP
iptables -t nat -A PREROUTING -i mpqemubr0 -s <vm-ip> -p udp --dport 853 -j DROP
```
(`-i`/`-s` scoping semantics and `REDIRECT`'s "changes the destination IP to the primary address of the incoming interface" behavior are the same primitives already quoted from `man 8 iptables`/`iptables-extensions` in `research/transparent-mitm-passthrough.md` §3.2–§3.3; DoT (port 853) has no `REDIRECT`-to-a-compatible-resolver option since it's a distinct TLS-wrapped protocol, so the simplest sound policy for it is an outright `DROP`/`REJECT`, forcing the VM to fall back to plain port 53, which the `REDIRECT` rule already captures). **This is a genuinely closeable gap: "run your own DNS resolver inside the VM, or point at a custom/external DNS server" is fully neutralized for classic DNS (port 53) and DoT (port 853) by ordinary DNAT scoped per-VM, using exactly the mechanism this design already relies on for 80/443.**

This also directly enables mitmproxy's own **ECH-stripping mechanism**, which turns out to already exist as a shipped, documented addon — `mitmproxy/addons/strip_dns_https_records.py`:
```python
class StripDnsHttpsRecords:
    def load(self, loader):
        loader.add_option(
            "strip_ech", bool, True,
            "Strip Encrypted ClientHello (ECH) data from DNS HTTPS records so that mitmproxy can generate matching certificates.",
        )
    def dns_response(self, flow: dns.DNSFlow):
        assert flow.response
        if ctx.options.strip_ech:
            for answer in flow.response.answers:
                if answer.type == types.HTTPS:
                    answer.https_ech = None
```
This addon runs against mitmproxy's own DNS-mode responses and, by **default** (`True`), deletes the `ech` SvcParam (key 5, per `mitmproxy/net/dns/https_records.py`'s `SVCParamKeys.ECH = 5`, matching the IANA-reserved key confirmed in RFC 9460's SvcParamKey registry — "`ech | RESERVED (held for Encrypted ClientHello) | N/A | IETF`," with the actual wire format specified in **RFC 9848**, per RFC 9849 §3.2's own cross-reference) from any HTTPS/SVCB DNS answer it serves, before the client ever sees it. If a client's only way to learn a destination's `ECHConfig` is this DNS record (the RFC 9849 §3.2-documented normal distribution path — "Domains which wish to use ECH must publish this configuration... This document defines the ECH configuration's format, but delegates DNS publication details to RFC 9460[/9848]"), and it never receives the `ech` param, the client has no config to encrypt against and will not attempt genuine ECH for that connection at all — it proceeds with an ordinary, real-SNI-in-the-clear ClientHello (possibly still GREASE-ECH per §1.3, which doesn't hide SNI anyway).

**The key dependency, stated precisely: this ECH-suppression mechanism only works if mitmproxy (or an equivalent resolver under the operator's control) is the DNS resolver the VM actually uses.** This is exactly what §5.2's DNAT rules above force. In other words, **the DNS-redirect control and the ECH-stripping control are the same lever** — forcing all VM DNS through a host-controlled resolver both closes the "custom DNS server" evasion directly, and is the prerequisite that makes mitmproxy's built-in `strip_ech` option actually effective, rather than something an agent can trivially route around by pointing at 8.8.8.8. Absent the DNS redirect, `strip_ech` is inert against this design's threat model — an agent that reaches an external resolver directly gets the unmodified `ech` param and can proceed with genuine ECH.

**Caveat, flagged explicitly as a limitation rather than a gap in the mechanism itself:** `strip_ech` only suppresses ECH configs learned via DNS. It does nothing against a client that has an `ECHConfig` hardcoded, cached from a prior resolution, or fetched by some non-DNS channel (RFC 9849 §3.2 itself notes "Other delivery mechanisms are also possible"). This is a narrowing-the-gap mechanism, not an absolute close.

### 5.3 DNS-over-HTTPS: not caught by the port-53 redirect, but not fully invisible either — it rides the existing 443 path

RFC 8484 (DoH) frames DoH explicitly as ordinary HTTPS: "Each DNS query-response pair is mapped into an HTTP exchange," over a normal HTTPS connection to whatever URI/host the client is configured with — there is no separate port or wire-level protocol signature distinguishing it from any other HTTPS traffic. This means the port-53/853 DNAT rule in §5.2 **does not catch DoH at all** — a DoH request is just an HTTPS POST/GET to port 443, exactly the traffic this design already redirects into mitmproxy.

That has a useful consequence, though: because this design already forces *all* outbound port-443 traffic through mitmproxy's SNI-peek layer (`research/transparent-mitm-passthrough.md` §1), a DoH request to a well-known provider (`dns.google`, `cloudflare-dns.com`, `doh.opendns.com`, etc.) is visible to mitmproxy's existing SNI-based rule matching **exactly like any other HTTPS connection** — no new mitmproxy mechanism is needed, only rule-table entries. An operator can add those hostnames as **Block** rules using the same host-exact mechanism already fixed by #5, with zero new plumbing. The residual gaps are the same structural ones this whole document is about, not unique to DoH:
- If the agent connects to a DoH resolver's IP directly with no SNI, it inherits §3's no-SNI-collapses-to-IP-matching gap.
- If the agent's DoH client uses (real or GREASE) ECH to the DoH endpoint, it inherits §1–§2's ECH gaps.
- A hostname blocklist is inherently incomplete against the long tail of self-hosted/CDN-fronted DoH servers (Cloudflare Workers, NextDNS custom endpoints, etc. — this design's rule table can list well-known public providers, but "DoH" as a protocol has no fixed, enumerable set of server identities the way port 53 has a fixed port number). An IP-range blocklist for "known public DoH resolver IPs" (nftables named set, `nft add rule ip filter output ip daddr @blackhole drop`, or the iptables `-d` equivalent) has the identical incompleteness — it only covers the IPs an operator curates, and CDN-fronted/anycast DoH ranges can overlap with ordinary web hosting IPs, risking false positives if the range is drawn too broadly.

**Conclusion for §5.3:** DoH is not a distinct networking-layer evasion requiring new Linux controls — it's a subset of ordinary HTTPS traffic this design already intercepts and can already Block by hostname. Its containment ceiling is exactly the ceiling of hostname-blocklist coverage (bounded, maintainable, but never exhaustive) plus whatever residual SNI/ECH visibility gaps apply to any other HTTPS destination.

---

## 6. Bottom line

Given the fixed constraints (transparent TCP mitmproxy, host-exact rules, default-Allow-unmatched), the realistic containment posture is a **detection/logging upgrade plus one genuinely closeable Linux-networking gap**, not a comprehensive block of any of the five evasions named in the ticket:

1. **ECH detection is buildable but structurally limited to "this client is ECH-capable," not "this connection is hiding something."** mitmproxy's `tls_clienthello` hook already exposes the full raw extension list (`ClientHello.extensions`, `mitmproxy/tls.py`) pre-handshake, so logging "extension 65037 present" (IANA-confirmed codepoint, RFC 9849) is a one-line addon. But RFC 9849 §6.2's GREASE-ECH mechanism means this signal cannot distinguish real hostname-hiding ECH from cover-traffic GREASE ECH that still exposes the real SNI — that ambiguity is by design, not an implementation gap that better parsing could close.
2. **A blanket "reject ECH" policy is not recommended.** It breaks a broad and structurally growing share of ordinary legitimate HTTPS (any GREASE-ECH client, any genuinely-ECH-fronted CDN origin — increasingly the default for major CDNs and browsers as of this research date), and per §2.1's RFC 9849 §6.1.4/§7.2/§5 finding, it doesn't even need to be enforced to stop silent MITM: **ECH's own accept-confirmation mechanism already makes silent on-path decryption cryptographically impossible** for any connection actually selected for Inject. The real residual risk on the Inject side is quieter than "bypass" — it's Inject rules silently not firing because the observed SNI is a decoy `public_name` (§2), which is a detection/alerting problem ("Inject rule configured for host X, but X's traffic volume through this proxy dropped to zero / decoy-SNI traffic increased" — an operational monitoring recommendation, not a protocol-layer fix), not something fixable at the TLS layer.
3. **No-SNI connections are already exactly what default-Allow-unmatched implies, and this is a rule-table property, not a mitmproxy gap.** mitmproxy parses "no SNI" cleanly (`.sni → None`) and already has its own IP-based fallback (`tlsconfig.py`'s `server.sni = client.sni or server.address[0]`) for the Inject path when it does apply — but the design's own host-exact rule matching degrades to matching on the raw DNAT-recovered destination-IP string (`next_layer.py`'s `hostnames` list), which no host-exact rule will ever match. Logging "SNI absent, connected directly to IP `<SO_ORIGINAL_DST recovered IP>`" is a one-line addition to the same hook and is the practical containment ceiling here: visibility, not prevention.
4. **Custom/external DNS resolvers inside the VM are a fully closeable gap**, using the identical DNAT mechanism this design already uses for 80/443 (`man 8 iptables` PREROUTING/`REDIRECT` semantics, already established in `research/transparent-mitm-passthrough.md` §3): redirect all outbound UDP/TCP 53 to a host-controlled resolver and drop 853 (DoT), scoped per registered VM's source IP on the bridge. This is not merely containment — it's closure, at the same confidence level as the existing 80/443 redirect design, using no new mechanism.
5. **That same DNS-redirect is also the precondition for mitmproxy's own built-in ECH-suppression addon (`strip_dns_https_records.py`, `strip_ech=True` by default) to do anything.** The addon strips the `ech` SvcParam from HTTPS/SVCB DNS answers it serves — but only if mitmproxy (or an equivalent host-controlled resolver) is actually the resolver the VM uses, which is exactly what item 4 forces. Combined, items 4–5 meaningfully narrow (not eliminate — RFC 9849 §3.2 explicitly allows non-DNS ECHConfig distribution) the population of connections that ever reach genuine ECH in the first place, as a prevention measure that sits upstream of the TLS-layer detection/observe-only posture in items 1–3.
6. **DoH is not a separate networking problem.** RFC 8484 confirms it's ordinary HTTPS with no distinguishing wire signature, so it already flows through this design's existing 443 interception and can already be Blocked by hostname using the existing host-exact rule mechanism (#5) against known-provider hostnames — no new Linux or mitmproxy capability required, only rule-table entries, with the same bounded-blocklist and same-as-any-other-host SNI/ECH visibility limitations as every other hostname.
7. **Direct-IP connections cannot be distinguished from "already-Allowed hostname's resolved IP" at the netfilter layer at all** — that distinction lives only in the TLS ClientHello, which is mitmproxy's domain (item 3), not iptables/nftables'. The only IP-layer lever available (`iptables`/`nftables` destination-IP allow/deny sets) is a strictly coarser, default-deny-by-IP security model that is out of scope given the fixed default-Allow-unmatched constraint.

**Net assessment:** given default-Allow-unmatched is fixed, none of the five evasions in the ticket can be turned into a hard Block by TLS-layer or IP-layer trickery alone — they were always going to reach the network under this design, exactly as the ticket's framing anticipated. The concrete, buildable delta this research identifies is: (a) two straightforward `tls_clienthello`-hook log lines (ECH-extension-present, SNI-absent) that give the operator real, if imperfect, visibility into which connections are using these techniques; (b) one fully closeable Linux-networking gap (forced DNS redirection, scoped per-VM, identical in mechanism to the existing 80/443 redirect) that both directly neutralizes custom/external DNS resolvers and activates mitmproxy's existing, already-shipped ECH-suppression addon; and (c) confirmation that DoH and direct-IP connections don't need bespoke handling — DoH is already inside the existing 443 interception surface and can be Blocked by hostname like anything else, and direct-IP connections are provably outside netfilter's ability to distinguish from legitimate traffic, so the honest posture there is observe-and-log via mitmproxy, not attempt-to-block via Linux networking.
