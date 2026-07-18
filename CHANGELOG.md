# Changelog

All notable changes to the **Python port** of ferm are documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

For the history of the original Perl implementation, see
[`reference/NEWS`](reference/NEWS).

## [Unreleased]

### Added

- `--nft` accepts the named arp `opcode` operands (`Request` ...
  `ARP_NAK`), mapping them through the arptables numbering (`ARP_NAK`
  is 9, which the IANA-following kernel readback spells `inreply`).
- `--nft` translates the arptables mangle target (`jump mangle` with
  `mangle-ip-s/d`, `mangle-mac-s/d`, `mangle-target`) to `arp saddr|
  daddr ip|ether set` rewrites behind the `arp htype 1 arp hlen 6 arp
  plen 4` guards; `mangle-target CONTINUE` emits a verdict-less rule
  and `RETURN` refuses (arptables rejects it).
- `--nft` translates `mod socket restore-skmark` to a `meta mark set
  socket mark` statement after the socket matches.
- `--nft` translates the ebtables MAC NAT targets: `snat to-source` /
  `dnat to-destination` (with their `snat-target`/`dnat-target`
  verdicts) become `ether saddr|daddr set`, unlocking the
  `grnet-synnefo` corpus config; `snat-arp`, `arpreply` and `redirect`
  keep refusing (no nft equivalent).
- `ferm(1)` and `import-ferm(1)` man pages, generated from POD templates
  and shipped in the deb/rpm/apk packages.
- Bash completion for `ferm` and `import-ferm`, generated from the
  option-documentation table and shipped in all three packages (apk: the
  `pyferm-bash-completion` subpackage).
- `ferm rollback --diff [SHA]`: read-only revision diff on stdout, and
  `-n/--limit N` for `--list`.
- `--describe` suggests close names on a typo (`did you mean: ...`).
- Forensic `Ferm-Version:` / `Ferm-Command:` git trailers in every
  etckeeper history commit.

### Changed

- etckeeper commit subjects are self-contained summaries: an imperative
  verb plus a counted delta (`ferm: apply ferm.conf (ip ip6, nft):
  +12/-3 rules, 1 policy`; `no changes` when the delta is empty).
- `ferm rollback --list` prints dated history entries and marks the
  first line ` (current)`.
- `ferm --help` is rendered from a single option-documentation table
  and now lists every option (`--noflush`, `--nft`, `--plan`, ... were
  missing) plus the `rollback` subcommand.
- The test aids `--test` (alias of `--remote`) and
  `--test-mock-previous` are deliberately documented in `--help` and
  the man page (the Perl manual documents only `--remote`): together
  with `--plan` they enable offline what-if planning without root.

### Fixed

- `--nft` emits the `restore-skmark` mark restore at the socket match's
  own position instead of after every other match: nft runs statements
  left to right, so the old tail placement made the restore conditional
  on later matches in the rule — marking fewer packets than iptables
  does.  The emission now matches iptables-translate.
- `--nft` refuses numeric arp `opcode` values past 65535 (`ar_op` is a
  16-bit field): arptables and the `nft -c` pre-check both reject them,
  but the dry-run surfaces (`--lines`, `--plan`) presented them as
  valid.
- `--nft` refuses `opcode 0` instead of emitting `arp operation 0`:
  arptables treats `--opcode 0` as a wildcard (verified live —
  arptables-nft installs no operation match at all), so the old
  emission inverted the semantics into match-nothing.
- The ebtables path refuses `domain eb table raw`/`mangle` with a clean
  error (`ebtables has no table 'raw'`) instead of crashing with a
  `KeyError` traceback; the Perl oracle dies on these tables too.
- `--nft` no longer emits chain types the bridge family rejects: `eb
  nat` chains were declared `type nat` (and `eb mangle OUTPUT` `type
  route`), which passed `--lines` but always failed the `nft -c`
  pre-check at apply time.  eb nat chains are now `type filter` on the
  hooks and priorities ebtables-nft uses (`dstnat`/`out`/`srcnat`),
  and eb filter chains moved from priority 0 to the bridge `filter`
  landmark (−200) — a chain rebuild on the next apply, and a changed
  hook order next to other bridge tables (libvirt, ebtables-nft).
  `eb raw`/`eb mangle`, which stock ebtables does not have and the
  ebtables path crashes on, now refuse cleanly under `--nft` instead
  of translating.
- `ferm rollback --interactive`: declining (or timing out) the
  post-apply confirmation now restores the config file to its committed
  state after the kernel rollback, instead of leaving the reverted
  config uncommitted on disk while the kernel keeps the pre-rollback
  rules (which also blocked the next rollback behind the dirty-worktree
  guard).
- The `ferm rollback --diff` error for a non-SHA value now explains how
  to combine a bare `--diff` with a non-default config path
  (`ferm rollback CONFIG --diff` or `--diff= CONFIG`).
- `import-ferm`: a bare `-` argument now reads stdin, matching Perl's
  `<>` operator (it used to be opened as a literal file named `-` and
  warned `Can't open -`).

## [0.1.0a8] - 2026-07-13

### Added

- **nft backend: the `osf` passive OS-fingerprint match.** `mod osf genre
  "<name>"` now translates to nft's native `osf name "<name>"` match
  (live-verified on nft v1.1.6, kernel 6.18.38). A negated genre becomes
  `osf name != "<name>"`; `ttl 1`/`ttl 2` map to nft's `ttl loose`/`ttl
  skip` levels while `ttl 0` (the strict default) needs no clause. The
  `log` option has no nft equivalent, so a rule carrying it refuses rather
  than silently drop the fingerprint logging. This closes the last iptables
  match module with a native nft counterpart; the remaining untranslated
  matches (`account`, `bpf`, `geoip`, `ipvs`, `psd`, `u32`, …) have no nft
  expression and continue to refuse cleanly.
- **nft backend: the CT target's `helper` option (vocabulary batch 11b,
  the second table object).** `CT --helper <name>` now translates to a
  native nft `ct helper` table object declaring the helper and its L4
  protocol, referenced by `ct helper set "<name>"` (live-verified on nft
  v1.1.6, kernel 6.18.38). The object name is content-addressed
  (`cthelper_<name>`, dashes folded to underscores), so the `--plan`
  differ compares it by name alone — which sidesteps the `l3proto` line
  the kernel adds on readback but the save form omits. The eight helpers
  the kernel exposes as single-protocol objects are supported (`ftp`,
  `irc`, `sane`, `pptp` over tcp; `tftp`, `amanda`, `snmp`, `netbios-ns`
  over udp); `sip` (registers both tcp and udp, so one object would narrow
  it), `h323` (no loadable object), and any unknown name refuse cleanly
  rather than emit a rejected load. A rule mixing `helper` with a
  translatable CT option (`zone`, `ctevents`, …) emits both; mixing it
  with the still-unsupported `expevents`/`timeout` refuses up front.
- **nft backend: the SECMARK target and table-object infrastructure
  (vocabulary batch 11b).** `SECMARK --selctx "<context>"` now translates
  to a native nft `secmark` table object holding the context, referenced
  by `meta secmark set "<name>"` (live-verified on nft v1.1.6). The object
  name is a content hash of the context, so identical contexts share one
  object. This adds the first *table object* to the nft backend: objects
  are declared before the chains, the `--plan` differ models them (a
  content-addressed name-diff, a fixed point against the kernel readback),
  and any object add/remove diverts the delta-apply to a full reload
  (`delete secmark` is refcount-unsafe mid-transaction — the set-removal
  precedent).
- **nft backend: the CONNSECMARK and HMARK targets (vocabulary batch
  11a).** Neither needs a table object; live-verified on nft v1.1.6:
  - `CONNSECMARK --save`/`--restore` → `ct secmark set meta secmark` /
    `meta secmark set ct secmark` (the CONNMARK save/restore shape);
  - `HMARK` → `meta mark set jhash <fields> mod M seed S [offset O]`,
    mapping the tuple (`src`/`dst`/`sport`/`dport`/`proto`) to jhash
    selectors, the seed to `0x`-hex, and dropping a zero offset. `mod`,
    `rnd`, and `offset` each accept a decimal or `0x`-hex operand; a
    leading-zero form (`010`) is refused rather than guessed, since
    iptables reads it as C octal. This maps the hash *distribution*, not
    xt's exact mark value (the same nft bar as recent/hashlimit). A
    per-field mask/prefix (jhash hashes fields whole) and the `spi`/`ct`
    tuple fields have no nft form and refuse.
- **nft backend: the `helper`/`nth` matches and four CT-target options
  (vocabulary batch 10).** All emissions are the exact kernel-readback
  spelling (verified live on nft v1.1.6) so `--plan` converges:
  - `mod helper helper <name>` → `ct helper "<name>"`;
  - `mod nth every N [packet P]` → `numgen inc mod N P` (the same numgen
    form as `mod statistic mode nth`; a non-zero `counter`/`start` has no
    numgen analogue and refuses rather than dropping the per-counter
    state);
  - the `CT` target's `ctevents` → `ct event set <bits>` (emitted in the
    kernel's canonical bit order — `new,related,destroy,reply,assured,`
    `protoinfo,label` — with the xt event names nft has no bit for,
    `helper`/`mark`/`natseqinfo`/`secmark`, refusing), `zone` →
    `ct zone set N`, and `zone-orig`/`zone-reply` → `ct original|reply
    zone set N`. A CT carrying several emits them in a fixed order
    (`notrack` → zone → event) so a multi-option CT round-trips. The
    `helper`/`timeout` options (which need object declarations) and
    `expevents` (no nft equivalent) still refuse — up front, so a rule
    mixing one with a translatable option never silently drops it.
- **nft backend: seventeen more match modules and the AUDIT target
  (vocabulary batch 9).** All emissions are the exact kernel-readback
  spelling (verified live on nft v1.1.6) so `--plan` converges:
  - `mod cpu` → `meta cpu`, `mod devgroup` → `iifgroup`/`oifgroup`
    (decimal; masks and symbolic groups refuse), `mod realm` →
    `meta rtclassid`, `mod cgroup` (classid) → `meta cgroup`;
  - `mod socket` incl. the bare load → `socket wildcard 0`,
    `nowildcard` → `socket wildcard <= 1`, `transparent` →
    `socket transparent 1` (`restore-skmark` refuses);
  - the extended `mod conntrack` tuple options: `ctorigsrc`/`ctorigdst`/
    `ctreplsrc`/`ctrepldst` (+ their `...port` twins) →
    `ct original|reply [ip|ip6] saddr|daddr / proto-src|proto-dst`,
    `ctproto` → `ct protocol`, `ctdir` → `ct direction`, and `ctexpire`
    → `ct expiration` with the kernel's asymmetric time canon (scalar
    `100` → `1m40s`, range `3600:7200` → `3600s-7200s`);
  - `mod connlabel` (numeric labels) → `ct label`;
  - `ahspi`/`espspi` → `ah spi`/`esp spi` (both imply their l4proto —
    the readback drops the `meta l4proto ah|esp` prefix);
  - the ip6 extension-header fields: `mh-type` → `mh type` (numbers
    respell to the readback names, e.g. 5 → `binding-update`),
    `hbh-len`/`dst-len`/`rt-len` → `hdrlength`, `rt-type` → `rt type`,
    `rt-segsleft` → `rt seg-left`, and `mod ipv6header ... soft` →
    `exthdr X exists` chains (the exact-set form without `soft`, and
    `auth`/`esp` headers, refuse);
  - `proto dccp dccp-types` → `dccp type { ... }` in ascending
    packet-type order, implying its l4proto (`INVALID` refuses — nft
    cannot parse it);
  - `mod policy dir in pol ipsec|none` → `meta ipsec exists|missing`
    (`dir out` and the per-element options refuse — fail-loud, never
    fail-open);
  - `mod rpfilter` incl. the bare load → the `fib saddr [. mark]
    [. iif] oif` forms with `loose`/`invert`/`validmark`
    (`accept-local` refuses);
  - `mod ecn`: `ecn-ip-ect N` → `ip|ip6 ecn not-ect|ect1|ect0|ce`,
    `ecn-tcp-cwr|ece` → `tcp flags cwr|ece`;
  - `mod ipv4options flags` → `ip option lsrr|ssrr|rr|timestamp|ra
    exists|missing` chains (`any` refuses);
  - `AUDIT type accept|drop|reject` → `log level audit` (the kernel
    audits identically for every type since 4.12).

- **nft backend: the SET target and the ban-list pattern.** `SET
  add-set $x src timeout N` / `add-set ... exist` / `del-set` translate
  to nft `add`/`update`/`delete @x { ip saddr [timeout ...] }`
  statements over a ferm-declared `@set` (external ipsets still refuse
  with a migration hint).  The mutated set is a runtime bucket: it must
  be declared empty (`@set $x = ()`), gets a `flags dynamic[,timeout]`
  declaration, and a `match-set` lookup on it now legally shares the
  name — the empty-set rule drop is lifted for SET-mutated sets, so a
  self-populating ban list (match + add in one config) works under
  `--nft`.  Timeouts respell to the kernel readback (`3600` → `1h`);
  `timeout 0` is a permanent element, exactly xt_set's semantics.
- **nft backend: `mod tcpmss mss` and `tcp-option` matches.**
  `mss 1400:1500` → `tcp option maxseg size 1400-1500` (negation `!=`),
  `tcp-option N` → `tcp option <kind> exists`/`missing`, with known
  kind numbers respelled to the kernel readback names (8 → timestamp,
  19 → md5sig, ...) and unknown kinds kept numeric.  Both match forms
  imply their l4proto, dropping the redundant `meta l4proto tcp`
  (SYNPROXY's `mss` companion keeps it — verified live).
- **nft backend: `icmp-type` / `icmpv6-type` match.** Named types
  translate per family (including the iptables aliases `ping`/`pong`/
  `ttl-exceeded` and the ip6 `neighbour-solicitation` → nft
  `nd-neighbor-solicit` respell), numeric types respell to the
  kernel-readback name so `--plan` converges, and the numeric
  `type/code` pair emits `icmp type X icmp code Y` (which even
  `iptables-translate` cannot express). A rule with an icmp-type match
  drops the redundant `meta l4proto`, matching the kernel readback.
- **nft backend vocabulary batch** (driven by corpus refusal
  frequency): `mod conntrack ctstate`, `mod multiport
  source-ports`/`destination-ports` (anonymous sets, colon ranges),
  `mod limit limit-burst` (paired into one `limit rate ... burst N
  packets` statement; a burst alongside several `limit` matches in one
  rule refuses — the pairing is ambiguous), `LOG log-level`, the
  `NFLOG` target (`log group N` with prefix/queue-threshold),
  `mod mark`/`mod connmark` matches
  and the `MARK set-mark` target (marks respell to the readback's
  8-digit hex), and dash-named chains (`fail2ban-ssh`). Wild-corpus
  coverage under `--nft` rises from 12/31 to 23/31 configs.
- **nft backend vocabulary, second batch.** `tcp-flags` (emitted in the
  kernel-readback bitwise form `tcp flags & (fin | syn) == syn`,
  including `ALL` and the `NONE` flag-absence form) and `!syn`;
  `TCPMSS` (`set-mss`, `clamp-mss-to-pmtu` → `tcp option maxseg size
  set rt mtu`); `mod owner` `uid-owner`/`gid-owner` (names resolve to
  the ids the readback prints) → `meta skuid`/`skgid`; `mod length` →
  `meta length`; `mod ttl` (`ttl-gt`/`ttl-lt` read back as `>`/`<`) →
  `ip ttl`; `mod mac mac-source` → `ether saddr` (lowercased); a
  full-mask `mark/0xffffffff` now matches as the plain equality it is;
  `TEE gateway` → `dup to`; `NOTRACK` → `notrack`; `TRACE` →
  `meta nftrace set 1`; `CONNMARK` `set-mark`/`save-mark`/
  `restore-mark` → `ct mark set ...`/`meta mark set ct mark`; arp
  `opcode` (numeric respell to `arp operation` names) and arp
  `source-mac`/`destination-mac` → `arp saddr/daddr ether`. A
  value-shape refusal now names the offending option (`option
  'match-set': multi-value ...`).
- **nft backend vocabulary, third batch: addrtype, QoS, match-set.**
  `mod addrtype` translates to `fib saddr|daddr type` (comma-lists emit
  as anonymous literals pre-sorted into kernel RTN order so `--plan`
  converges; negated lists translate too; `limit-iface-in`/`-out`
  qualify the selector with `. iif`/`. oif`; `throw`/`nat`/`xresolve`
  refuse by name — they have no fib equivalent). `mod dscp` and the
  `DSCP` target translate with the value respelled to the kernel
  readback's class name (including `lephb`/`va`, which the iptables
  class table does not know; unnamed codepoints stay hex); `CLASSIFY
  set-class` emits `meta priority set` in the readback canon (leading
  zeros stripped, `ffff:ffff` → `root`, `0:0` → `none`). `mod set
  match-set $var` now translates when `$var` is a ferm-owned `@set`
  (dual-stack rules filter the set per family; the negated form emits
  `!=`); a bare ipset name refuses with a migration hint — nftables
  cannot reference external ipsets — and under the iptables backend a
  `@set`-backed `match-set` now refuses cleanly instead of dying with
  an internal error. `mod tos` / `TOS` refusals state the honest
  reason (no single nft selector covers the 8-bit TOS byte with a
  mask; nft exposes dscp and ecn separately). Wild-corpus coverage
  under `--nft` rises from 23/31 to 24/31 configs.
- **nft backend vocabulary, fourth batch: ct status, NFQUEUE, SYNPROXY,
  TTL/HL, NETMAP, masked marks.** The `ctstate` SNAT/DNAT pseudo-states
  translate to `ct status` (negation emits the masked bang form
  `ct status ! snat,dnat` — the only spelling whose bytecode means
  "none of the bits set"; a list mixing them with real states refuses:
  it means one OR across two ct registers, which no single nft rule
  can express), and `mod conntrack ctstatus` translates alongside
  (`SEEN_REPLY` → `seen-reply`; `NONE` has no nft spelling and
  refuses). `NFQUEUE` emits the readback's `queue [flags
  bypass,fanout] to N` (`queue-cpu-fanout` without `queue-balance`
  refuses, as xt itself does). `SYNPROXY` emits `synproxy` with its
  parts in the kernel's fixed order and `mss`/`wscale` as a pair
  whenever either is given (the nft frontend raises both kernel flags
  together); `ecn` has no nft twin and refuses. `TTL ttl-set` / `HL
  hl-set` become `ip ttl set` / `ip6 hoplimit set` (the inc/dec
  variants refuse — nft has no payload arithmetic), and the `mod hl`
  matches become `ip6 hoplimit` (`>`/`<` readback canon). A
  partial-mask `mark`/`connmark` match emits the infix bitwise form
  (`meta mark & 0x… == 0x…`, 8-digit hex operands), and `MARK
  set-xmark` with a full mask folds to the plain `meta mark set`.
  `NETMAP` translates to nft's prefix-to-prefix NAT map (`dnat ip
  prefix to ip daddr map { A : B }`) when a built-in nat chain names
  the hook side and a same-side address match of equal prefix length
  names the map key; every other shape refuses with the reason. The
  adversarial `boundary-values` corpus config now translates
  end-to-end.
- **nft backend vocabulary, fifth batch (stateless): statistic,
  pkttype, TCPOPTSTRIP.** `mod statistic` translates both modes: `mode
  random probability p` becomes the readback's masked sampler `meta
  random & 2147483647 < round(p·2³¹)` (the `p = 1.0` threshold sits
  above the mask, so the match is always true, as intended), and `mode
  nth every N packet P` becomes the bare `numgen inc mod N P` (xt's
  0-based `--packet` defaults to 0). `mod pkttype` becomes `meta
  pkttype`, with xt's `unicast` respelled `host` on kernel readback and
  the negated form supported. The `TCPOPTSTRIP` target becomes a series
  of `reset tcp option <x>` statements (one per stripped option, in
  order): the mnemonics map to nft keywords and known option numbers
  respell to names (`8` → `timestamp`) while unknown numbers stay
  numeric; the rule must carry a `tcp` protocol match. Refusals are
  fail-closed (a negated or unknown statistic mode, a probability
  outside `[0, 1]`, `nth` without `every` or with `packet ≥ every`, a
  pkttype outside unicast/broadcast/multicast, a TCPOPTSTRIP without a
  tcp match or naming an option outside the map and not a byte number).
- **nft backend vocabulary, fifth batch (stateful): `mod recent` and
  `mod hashlimit`.** Both translate to an implicit named dynamic set
  (`add set ... { type ...; size 65535; flags dynamic[,timeout]; }`)
  and an `update @<set> { <key>[ timeout <t>][ limit rate [over] R burst
  B packets] }` statement that both records the key and gates the rule's
  verdict. `mod recent set`/`rcheck`/`update` map to one set named
  `recent_<name>` (rsource → `saddr`, rdest → `daddr`); every rule of a
  name emits the identical calibrated element spec, so `R = T·H/S`
  (integer-reduced to an nft rate unit), `B = T·H − 1`, with `T` the
  number of update-rules touching the name (`hitcount 4 seconds 60`
  across a check rule and a bare `set` gives `rate over 8/minute burst
  7`). `mod hashlimit` maps to `hashlimit_<name>`: `hashlimit-upto` is
  the conform rate and `hashlimit-above` the `over` rate (burst explicit,
  default 5); `hashlimit-mode` builds the key (`srcip`/`dstip` →
  `ip[6] saddr`/`daddr`, `srcport`/`dstport` → `<proto> sport`/`dport`,
  concatenated in a fixed order with a matching concatenated set type),
  `hashlimit-srcmask`/`dstmask` narrow an address key with `& <mask>`,
  and the element timeout comes from `hashlimit-htable-expire` (or the
  rate period, with a bare `/second` rate carrying no timeout). Emission
  matches the kernel readback byte for byte (time canon `90s` → `1m30s`;
  `flags dynamic,timeout` with no space), and the `plan.py` differ now
  excludes a dynamic set's kernel-accrued elements from the diff so
  `--plan` converges and a delta apply never wipes the tracked state.
  Refusals are fail-closed (recent `remove`/`rttl`/`reap`/`mask`, any
  negation, a name with conflicting seconds/direction/hitcount or no
  seconds anywhere, a `set` with a real verdict when the name has check
  rules, an irreducible rate; hashlimit without a mode, a port mode with
  no tcp/udp protocol, byte or fractional rates, an invalid identifier,
  and a name reused with a conflicting shape or colliding with a user
  `@set`). Two more corpus configs now translate under `--nft`
  (`ferm-tools-example` via hashlimit, `chain-maze` via recent).

  Sanctioned semantic deviations from xt (documented for parity
  reasoning): xt_recent's sliding window becomes an nft token bucket —
  an average-rate approximation whose stateful expression is fixed when
  the element is created, so every update-rule of a name must emit the
  identical spec; xt `rcheck` is read-only but the nft update form
  refreshes the element's timestamp and taxes a token; and an element
  expires `S` seconds after its last touch. The calibration is pinned
  against real xt_recent (first drop within the `[H−1, H+1]` jitter
  window; opt-in `nox -s recent_calibration_e2e`).
- **nft backend vocabulary, sixth batch: TPROXY, CT notrack, NAT flags,
  `mod time`.** `TPROXY` emits `tproxy to :P` (bare `on-port`), `to A:P`
  (`on-ip`, bracketed for ip6), an optional `--tproxy-mark` folded to the
  kernel's and/or mark rewrite, and a terminal `accept`; it requires a
  transport match and `on-port` (the xt oracle refuses otherwise). `CT
  notrack` maps to `notrack` (the same spelling as the standalone
  `NOTRACK` target). The NAT flags `--random` / `--random-fully` /
  `--persistent` append to `snat`/`dnat`/`masquerade`/`redirect` in the
  fixed kernel-readback order (`random`/`fully-random` first, `persistent`
  last; `--random-fully` respells to nft's `fully-random`), unblocking
  `rwthctf2012-vpn`. `mod time` folds into up to three independent
  selectors: `meta hour` (a clock range, zero seconds trimmed per
  boundary, xt defaults `00:00`/`23:59:59`), `meta day` (weekday names in
  nft numeric order, a single day unbraced, `--weekdays` negation as
  `!=`), and `meta time` (a full-datetime range or an open `>=`/`<=`
  bound). Two more corpus configs now translate under `--nft` (`raw-edge`
  via TPROXY + CT notrack, `rwthctf2012-vpn` via the NAT flags).

  Deliberate refusals (no faithful nft equivalent): the `CHECKSUM` target
  (kernels since 4.19 handle virtio checksum offload without it, and the
  nft CLI cannot call xt targets), and `mod time`'s `monthday` (no meta
  selector), `kerneltz`, and `contiguous` (local-time and cross-midnight
  semantics nft's UTC-anchored evaluation cannot mirror).
- **nft backend vocabulary, seventh batch: connbytes, connlimit, quota,
  iprange, mark arithmetic.** `mod connbytes` becomes a `ct [original|
  reply] bytes|packets|avgpkt` counter match with the kernel-readback
  comparison spelling (`>=`/`<`, not iptables-translate's `ge`/`lt`): an
  open `N:` bound (and a bare `N`, which xt reads as `N:`) is `>= N`, `:M`
  the closed `0-M` interval, `N:M` the `N-M` interval, and negation flips
  `>=` to `<` or prefixes `!=`. `mod connlimit` translates to an implicit
  **per-rule** dynamic set plus `ct count [over] N`
  (`connlimit-upto` → `count N`, `connlimit-above` → `count over N`, each
  negating to the other; `connlimit-mask` narrows the `ip|ip6 saddr|daddr`
  key with `& <netmask>`, `connlimit-daddr` picks the destination side) —
  each rule owns its set (xt allocates one `nf_conncount` tree per rule),
  named by a stable content hash so inserting an unrelated rule never
  renames it. `mod quota` becomes a `quota <n> <unit>` statement with the
  kernel's unit canon (the largest of `bytes`/`kbytes`/`mbytes` that
  divides evenly; there is no `gbytes`, so 2³⁰ reads back as `1024
  mbytes`, and an indivisible count stays in bytes). `mod iprange`
  `src-range`/`dst-range` become `ip|ip6 saddr|daddr A-B` address ranges
  (negated with `!=`; a bound of the wrong family refuses). The `MARK` and
  `CONNMARK` targets gain full masked mark arithmetic: `set-xmark v/m`
  folds to the readback and/or canon (`meta mark`/`ct mark` register),
  `set-mark v/m` uses xt's effective mask `m' = v|m` (so `0xff/0x0f` is
  legal), and `and-mark`/`or-mark`/`xor-mark` emit the bitwise register
  rewrite (`&`/`|`/`^`). connbytes/connlimit/quota/iprange are stateful or
  interval statements kept off the collapse/vmap passes, so two rules'
  counters never merge.

  Deliberate refusals (no faithful nft equivalent): `CONNMARK`
  `save-mark`/`restore-mark` with `--nfmask`/`--ctmask`/`--mask` (moving
  bits between the packet and ct registers under two independent masks,
  which nft's grammar cannot express and iptables-translate mistranslates
  into a form the kernel silently collapses).

### Changed

- **`--plan`: the single 1800-line `plan.py` is now the layered `plan/`
  package** (`model` → `readback` → `diff` → `delta` → `render`), with
  the layer order enforced by an import-linter contract and the public
  seam re-exported from `__init__` — pure code motion, no behaviour
  change, mirroring the `backend/nft/` split below.
- **nft backend: the single 5000-line `backend/nft.py` is now the
  layered `backend/nft/` package** (`model` → `chains`/`sets` →
  `matches` → `stateful`/`verdicts` → `assemble` → `backend`), with the
  layer order enforced by an import-linter contract and the public
  seam re-exported from `__init__` — pure code motion, no behaviour
  change (byte-identical golden/corpus output).
- **nft backend: every nft subprocess is pinned to `TZ=UTC`.** nft
  converts a `meta hour`/`meta time` literal between local time and the
  UTC the kernel stores using the process `TZ` on both parse and print,
  so the apply (`nft -c`, `nft -f -`) and snapshot (`nft list table …`)
  spawns now run under `TZ=UTC`. The emitted clock then means exactly
  what xt_time (without `--kerneltz`) means — UTC — and `--plan` stays
  diff-free on any host regardless of its zone or DST state. The iptables
  call sites are untouched (`TZ` is immaterial to `iptables-save`).

### Fixed

- `import-ferm` save-file parsing and `--def` name parsing matched with
  Unicode `\w`/`\S`/`\b` where the Perl tool matches raw bytes: a
  non-ASCII byte in a table or chain name (or a `--def` name) was
  silently accepted where Perl warns or rejects. The dispatch patterns
  are pinned to `re.ASCII`, restoring byte parity.
- **nft backend: `proto mh` emitted a script nft rejects at apply
  time.** `mh` is an nft keyword, so the emitted `meta l4proto mh` was
  a syntax error that `--lines`/`--plan` never surfaced; the protocol
  now emits the kernel spelling `mobility-header`.  Same class:
  `hopopt` now emits `ip` (protocol 0's readback name) and the
  ipv6-route/ipv6-frag/ipv6-nonxt/ipv6-opts protocol numbers respell
  to their readback names instead of staying numeric.
- **nft backend: bare match-module loads no longer silently drop.**
  `mod hbh`, `mod dst`, `mod eui64` (whose bare load IS the match:
  extension-header presence, EUI-64 check) and `mod limit` (whose bare
  load is a real limiter at xt_limit's default rate) used to vanish
  from the translated rule, leaving an unconditional verdict — a
  fail-open widening the iptables backend does not have (`-m eui64` is
  emitted verbatim there). A bare load now refuses at translate time
  unless the module is semantically inert without options (`state`,
  `conntrack`) or contributes at least one option to the rule.
- **nft backend: the eb `MARK` target no longer emits `jump mark`.**
  The parser rewrites eb `MARK` to ebtables' lowercase `mark` spelling,
  which slipped past the eb-target guard and fell through to the
  user-chain branch — a jump to a chain that never exists, rejected
  only at apply time. It now refuses cleanly like the other eb targets.
- **nft backend: `mod recent` with an effective hitcount of one no
  longer emits `burst 0`.** A lone check rule with `hitcount 1`
  produced `limit rate over ... burst 0 packets`, which nft rejects at
  apply time ("packet limit burst must be > 0"), so a config legal
  under iptables failed to install. The degenerate window now emits
  the limitless `update @recent_...` element — "match from the first
  in-window packet", exactly what the `B = T*H - 1` calibration
  approaches as the burst shrinks.
- **nft backend: `hashlimit-htable-max` is refused instead of silently
  ignored.** The translation pins the dynamic set to the kernel's
  implicit `size 65535` for `--plan` readback parity, so a user-set
  entry cap was silently overridden — a deliberate memory ceiling
  quietly grew to ~65k entries. It now refuses like the other
  no-nft-equivalent options. `hashlimit-htable-size` and
  `hashlimit-htable-gcinterval` (performance-tuning knobs with no
  match semantics) remain accepted and deliberately ignored.
- **Packaging: the shipped `ssh-throttle.conf.example` now translates
  under `--nft`.** The example's `mod recent name SSH-THROTTLE` carried
  a dash, which is invalid in an nft set identifier, so copying the
  advertised drop-in into `ferm.d/` broke `--nft` installs with
  "invalid recent name". The list is now named `SSH_THROTTLE`
  (xt_recent names are free-form; iptables semantics unchanged).
- **nft backend: registered targets no longer fall through to chain
  jumps.** An extension target with no nft translation (`TARPIT`,
  `MIRROR`, `AUDIT`, ...) used to emit `jump TARPIT` — a jump to a
  chain that never exists, rejected only by the apply-time `nft -c`
  while `--test`/`--noexec --lines` reported success. Any registered
  target keyword without a translation is now a clean translate-time
  refusal, like the eb-target guard.
- **nft backend: `--plan` convergence for limit rates and service
  ports.** Abbreviated xt_limit units (`10/min`, `10/m`, bare `5`)
  expand to nft's full spelling instead of emitting a script `nft -f`
  rejects, and service-named ports (`ssh`, `http`) resolve to the
  numbers the kernel readback prints (a named port previously left
  `--plan` diffing an applied ruleset forever).
- **nft backend: negated multi-member `ct state` lists carried the
  wrong semantics.** `! state (ESTABLISHED RELATED)` used to emit
  `ct state != established,related`, which nft compiles to a
  whole-register comparison — true for nearly every packet — instead
  of iptables' "none of these states"; it now emits the masked bang
  form `ct state ! established,related` (verified against the netlink
  bytecode). State lists are also pre-sorted into kernel bit order:
  the readback re-sorts `related,established`, so the source-order
  emission left `--plan` diffing an applied ruleset forever.

### Testing

- Packaged-config gate (`tests/corpus/test_packaged_config.py`): the
  default `/etc/ferm/ferm.conf` shipped by every package — alone and
  composed with the advertised ssh-throttle drop-in — must compile
  bug-for-bug with the Perl oracle on the iptables path, translate
  cleanly under `--nft` with the security-relevant shape pinned
  (default-drop, SSH/ICMP admission, the calibrated recent limit), and
  pass a live `nft -c` where available.
- Review follow-up batch: regression pins for the two fixes above,
  mutation-driven kill tests (option-loop continuation after each
  dynamic-set module, `_hashlimit_key` mode matrix, clock/mark/mask
  boundary operators, HL and SNAT verdict threading), golden pairs
  pinning array unfolding through connlimit (four distinct
  content-hash sets) and recent (one shared set), ip6 parity checks
  for the family-agnostic constructs, a `flags dynamic` invariant pin,
  and full-message anchors across the recent/hashlimit/connlimit
  refusal batteries.
- The coverage session now measures the subprocess-driven golden
  harness too (`COVERAGE_PROCESS_START` + `parallel` data files):
  code exercised only through `python -m pyferm` children — the
  entire nft golden suite — was previously invisible to the coverage
  floor and the diff-cover patch gate.
- New nft-backend gates formalizing the review probes: a dichotomy
  sweep over the full synthetic module matrix (translate cleanly or
  refuse cleanly, never a jump to a registered target), a unit sweep
  asserting no registered target ever emits as a chain jump, and an
  opt-in live suite (`unshare -rn` + `nft`) validating the whole
  translated vocabulary against `nft -c` and pinning `--plan`
  convergence after a real apply. Golden pairs `icmp_types`,
  `flags_targets` and `match_extras` pin the emitted text.
- The containerized readback pin (`nox -s nft_readback_e2e`) gains the
  fourth-batch canon: ct bit-order and bang-form respells, `queue …
  to`, the synproxy part order and mss/wscale pairing, 8-digit
  masked-mark hex, the NETMAP prefix map, and `ip ttl set` /
  `ip6 hoplimit set`; the `ct_queue_netmap` golden pair and the live
  vocabulary suite cover the same batch end-to-end.

## [0.1.0a7] - 2026-07-06

### Added

- **Chain-graph visualisation (`--graph`).** Print the chain control-flow
  graph as a d2 (default) or Graphviz DOT diagram; choose the renderer
  with `--graph-format {d2,dot}`. Read-only and eval-free.
- **Introspection modes (`--list-modules`, `--describe`).** `ferm
  --list-modules` lists every supported netfilter module (protocol,
  match, target) plus the built-in configuration keywords; `ferm
  --describe NAME` shows the option table of a module, the signature
  of a built-in keyword or `@`-function, a shortcut expansion, or
  which module provides an option of that name. The parser-level port
  switches (`sport`, `dport`) are covered as built-in rule keywords.
  Port-only, read-only terminal modes: no input file, no kernel or
  config access, and no other switch combines with them.
- **Lint severity tiers and gating threshold.** `ferm --lint` now runs
  six checks through a severity-ordered registry: `jump-cycle` (error),
  `unused-definition`, `undefined-jump`, `unreachable-chain`,
  `duplicate-definition` (warnings) and `deprecated-keyword` (info),
  printed as `<severity>: <message>` lines sorted by severity, check
  and message. Three first-slice false positives/negatives are closed:
  double-quoted `"$x"` interpolation now counts as a use, `realgoto` is
  recognized as a jump edge, and `@def &f` functions are tracked (an
  uncalled function reports as `unused definition: &foo`). The new
  `--lint-fail-level={error,warning,info}` sets the CI gating
  threshold; bare `--lint-strict` still gates at the warning level and
  the default exit stays `0`. Known limits are documented and
  test-pinned: the cycle graph flattens `(domain, table)` and both
  `@if` branches and credits nested `@def` bodies to their enclosing
  chain (phantom cycles possible), a cycle routed through a function
  call stays invisible, reachability is in-degree only, and
  `jump $var` targets stay invisible.
- **Static analysis mode (`--lint`).** `ferm --lint` reads a single config
  file and structurally parses it — no variable substitution, no module
  loading, `@include` is not expanded — then reports two classes of
  findings, one per line on stdout: `warning: unused definition: $foo` for
  a declared `@def` never referenced, and `warning: jump to undefined
  chain: BAR` for a `jump`/`goto` whose target chain is declared nowhere.
  Findings are sorted, with all `unused definition` warnings printed before
  all `jump to undefined chain` warnings. By default findings do not change
  the exit code (`0`), so `--lint` is safe to run against someone else's
  CI; `--lint-strict` escalates any finding to exit `2` for opt-in gating.
  Exit `1` covers a file-read error, an internal bug, or a usage error (an
  incompatible flag combination, or other than exactly one input file) —
  `--lint` does not validate syntax (the structural parser is error-tolerant)
  and
  inherits the analyzers' known false positives/negatives (for example a
  variable used only through string interpolation, or a chain declared
  only in another domain/table).

### Changed

- **A modified-set diff under `--plan --nft` shows both sides.** A changed
  named set now renders its current (live) elements alongside the desired
  ones, so the diff shows what the elements change *from*, not only what
  they change *to*.

### Fixed

- **`--nft` refuses ebtables target keywords instead of mistranslating
  them.** In the `eb` domain the `snat`/`dnat`/`redirect`/`arpreply`
  targets share companion option names with the inet NAT targets, so
  the nft backend silently rendered them as a jump to a chain that was
  never created and dropped the MAC rewrite (`nft -c` then rejected the
  script). They now fail up front with a clean "not yet supported"
  error, like every other untranslatable construct.
- **`--nft` translates a trailing `+` interface wildcard to `*`.** nft
  treats `+` in an interface name as a literal byte, so an untranslated
  `eth+` silently matched nothing while `nft -c` still accepted the rule.
  A trailing `+` now renders as nft's `*` in both the match and the
  named-set element; an interior `+` stays literal. A named interface set
  holding such a prefix element also gains `flags interval`, which nft
  requires for wildcard elements.
- **`--plan --nft` converges on sets with quoted elements.** Sets whose
  elements render quoted (interface-name sets like `"eth0"`) previously
  kept config order while nft reads sets back lexically, so any
  non-lexical config order produced a phantom diff on every run —
  `--plan` never reported clean, and each delta apply rebuilt the chain
  and reset its counters. Quoted elements are now canonicalized and
  sorted like the other element kinds.
- **`ferm rollback` refuses `--interactive` without a terminal.** Run
  non-interactively, the rollback previously checked out the old config
  in git while the kernel confirmation read EOF and rolled the ruleset
  back, leaving the worktree and the kernel out of step. The same tty
  guard as the apply path now runs before any git or kernel action,
  covering both the bare and the `--to` forms.
- **`@resolve()` reports unparsable AAAA record data as a ferm error**
  instead of escaping with a bare `AddressValueError` traceback. (The
  Perl oracle silently mangles such bytes and exits 0; the clean error
  is a sanctioned divergence.)

## [0.1.0a6] - 2026-06-30

### Added

- **Read-only plan mode (`--plan`).** `ferm --plan` computes the ruleset and
  reports what would change against the live kernel without applying anything,
  for both the default `iptables` backend and `--nft`. `--plan-format` selects
  a `structured` summary (default) or a unified `diff`. The run is exit-coded:
  `0` when nothing would change, non-zero otherwise. `@preserve` is reported as
  unsupported under `--plan`.
- **Config history and rollback via etckeeper.** When
  [etckeeper](https://etckeeper.branchable.com/) manages `/etc`, every
  successful apply records a commit in the `/etc` history with a semantic
  message describing the kernel-ruleset delta (for example `filter/INPUT:
  +3 -1`). `ferm rollback`, `rollback --list`, and `rollback --to <sha>` revert
  `/etc/ferm` to an earlier revision and re-apply it (git-only; the source is
  restored and regenerated, not the exact prior bytes). On by default when
  etckeeper is installed; `--no-etckeeper` turns it off for a single run.
- **Named nft sets via `@set`.** A `@set $name = (...)` declaration binds a
  reusable set of ports, addresses, or interface names. Under `--nft` the set
  is emitted as a first-class nft object (`add set` + `add element`) and the
  rule references it by name (`tcp dport @name`); a port set with a range
  carries `flags interval`. Under the default `iptables` backend the same
  `@set` reference is expanded back to its element list, so the rule unfolds to
  the identical cartesian product a literal list would produce — a config using
  `@set` works on both backends. `ferm --plan --nft` reports set additions,
  removals, and element changes alongside chain and rule diffs.
- **Base-chain priority knob (`--nft`).** A built-in chain may carry an
  explicit nft priority, written after the chain name: `chain FORWARD
  priority -1 { ... }`. The priority may be a plain integer or an nft
  landmark name with an optional offset, mirroring nft's own spelling:
  `priority filter`, `priority dstnat - 10`, `priority security + 1`
  (landmarks resolve per family). It overrides the hardcoded default (e.g. a
  filter forward chain's `0`) so ferm's table can be ordered deterministically
  against a coexisting one — for instance ahead of docker's forward chain,
  which also sits at priority `0`. nft-only: the integer is rejected under the
  `iptables` backend (chains have no priority there) and on a non-base chain.
  A delta-apply that changes an existing chain's priority deletes and recreates
  that chain (its counters reset; siblings are untouched), since nft cannot
  redeclare a chain with a different priority in place; `ferm --plan` reports
  it as a chain rebuild.
- **Chain and table names are validated against a safe alphabet.** A
  config-supplied chain or table name must match `[A-Za-z0-9_.+-]`; anything
  outside it is rejected at the backend border before any save text or
  command line is built. This is defense-in-depth for the slow path (one
  `iptables`/`ebtables` call per rule), where `eb`/`arp` rules run by default:
  a name carrying a shell metacharacter is refused rather than interpolated
  into the command. Valid configs are unaffected.

### Changed

- **`--nft` applies an incremental delta by default.** Instead of flushing and
  rebuilding ferm's table on every apply, the `--nft` backend now diffs the
  desired ruleset against the live one and applies only the changed sets,
  chains, and rules in a single atomic `nft -f -` transaction, preserving
  untouched counters. `--full-reload` restores the previous flush-and-rebuild
  behaviour. A first apply, an empty live snapshot, or a set retype falls back
  to a full reload automatically; a delta that would delete a set falls back
  too (the delta path never deletes a set).
- The `--nft` backend folds adjacent rules that differ in a single value
  into anonymous nft sets (`tcp dport { 22, 80, 443 }`), producing more compact
  output. Negated matches and per-rule-distinct statements stay linear.
- **`--nft` folds single-key rules with distinct verdicts into a verdict map**
  (`tcp dport vmap { 22 : accept, 80 : drop }`) and collapses address ranges
  into interval sets, for more compact output.

### Packaging

- **Native `.rpm` and `.apk` packages.** Alongside the PyPI wheel/sdist, the
  `.deb`, and the standalone binary, RPM (`.rpm`, for RPM-based distros) and
  Alpine (`.apk`, OpenRC) packages are now built and smoke-tested. Like the
  `.deb` they replace a prior `ferm` and ship the starter config un-applied
  (anti-lockout); the Alpine package carries a posture-downgrade advisory
  across the two-transaction `apk` migration.

### Security

- **The standalone binary refuses to run from a writable dist directory.**
  Run as root, it verifies its own `ferm.dist/` directory is owned by root and
  not group- or world-writable before loading its bundled shared objects,
  otherwise printing how to fix the permissions. This blocks a local attacker
  from planting a malicious shared object next to the binary.
  `FERM_SKIP_DIST_PERM_CHECK=1` overrides it for a deliberately non-standard
  layout.

### Notes

- **The first `ferm --plan --nft` after upgrading may show a one-time large
  diff.** When a config adopts `@set` or rule/verdict-map folding, the live
  kernel still holds the previous linear rules, so each affected rule appears
  as a change (for folding, `remove (N linear) + add (1 set)`) until the next
  apply. This is expected and resolves on the first apply.

## [0.1.0a3] - 2026-06-16

The Python port (`src/pyferm/`). Phase 1 reproduces the Perl
implementation's behaviour and emits `iptables` rulesets; its output is
validated byte-for-byte against the Perl oracle kept in `reference/`.

Phase 2 adds an **opt-in native `nftables` backend** behind `--nft`. The
default backend stays `iptables`, so existing configurations and output
are unchanged unless `--nft` is passed.

### Added — packaging

- **PyPI wheel and sdist** (`pip install ferm`). Built with `uv build` and
  published via Trusted Publishing — no token secrets stored in CI. The
  package name on PyPI is `ferm`; the `dns` extra (`pip install ferm[dns]`)
  pulls in `dnspython` for full record-type support in `@resolve()`. Version
  is derived from the `py-v<PEP440>` git tag through `hatch-vcs`, so the
  wheel version and the tag are always the same source.
- **Native `.deb` package** (`pyferm`). Installs `/usr/bin/ferm` and
  `/usr/bin/import-ferm` and declares `Provides: ferm`, `Conflicts: ferm`,
  `Replaces: ferm` so it is a drop-in replacement for the Perl `ferm` Debian
  package — installing `pyferm` removes the Perl package and satisfies any
  dependency that requires `ferm`. The `.deb` ships a starter
  `/etc/ferm/ferm.conf` (DROP policy on `INPUT`; only SSH on port 22 by the
  `ssh` service name and the RFC 4890 ICMPv6 essentials subset are accepted)
  and a `ferm.service` unit that is **not** enabled or started on install
  (anti-lockout). Drop-in fragments under `/etc/ferm/ferm.d/*.conf` are
  merged at runtime. See the installation section of the
  [README](README.md) for safety notes before enabling the service.
- **Standalone binary distribution** for **Linux x86_64** (glibc **2.28**
  or newer), published as `ferm-<version>-linux-x86_64.tar.gz`. It bundles
  its own Python runtime and `dnspython`, so the target host needs no
  Python install; it does not bundle `iptables` / `nft`, which must be
  present at runtime. Unpacking yields a `ferm.dist/` directory with the
  `ferm` binary and an `import-ferm` symlink. **Install invariant:** the
  binary loads bundled shared objects from its own directory, so keep it
  inside `ferm.dist/` and link to it (don't copy the bare binary out);
  unpack into a root-owned, non-world-writable directory. See the
  installation section of the [README](README.md) for the full provenance
  and threat-model notes.
- **Dynamic release version from git tag (`hatch-vcs`).** The distribution
  version is derived from the `py-v<PEP440>` git tag via `hatch-vcs`, so
  the wheel, sdist, binary, and `.deb` all carry the same version as the tag
  with no manual edit required. The build verifies the tag and the derived
  version agree before publishing.
- **Bundled third-party license texts.** The tarball ships a `LICENSES/`
  directory with the verbatim license text of every native library frozen
  into the binary (CPython, dnspython, OpenSSL, libffi, bzip2, xz, mpdecimal)
  plus a manifest. The build fails closed if any bundled library has no
  license text, so the artifact is never published without its notices.
- **glibc-floor release gate.** Releases now load the packaged binary on a
  pinned glibc 2.28 image (not the build image), so a symbol above the
  advertised floor fails the release rather than a user's old distro.

### Added — Phase 2 (native nft backend)

- **Opt-in `--nft` native nftables backend.** Translates the structured
  rule into a native nft ruleset and applies it atomically via
  `nft -f -`. It uses the nft *text* wire only and has no dependency on
  nft's JSON / `libjansson` build. `--nft` is strictly opt-in; the
  default remains the `iptables` backend.
- **`--nft` validates the ruleset with `nft -c -f -` before applying.**
  The applier runs nft's text `--check` (a netlink validation that
  installs nothing) first and only pipes the real `nft -f -` once it
  passes, surfacing nft's own diagnostic *before* any kernel change
  instead of a generic apply failure.
- **`--nft --interactive --shell` emits a working anti-lockout net.** The
  generated shell script snapshots ferm's table (`nft list table`) before
  applying, and after the confirmation timeout deletes the freshly-applied
  table and reloads the snapshot (`nft -f`) — mirroring the live rollback,
  so an admin who never confirms is restored. The script also echoes the
  rollback to stderr, so the otherwise-silenced restores (`2>/dev/null`)
  no longer revert a timed-out admin without a word.

### Changed — Phase 2 (native nft backend)

- **`policy DROP` semantics differ under `--nft`.** The nft backend owns
  a single `table <family> ferm` and does not take over the monolithic
  kernel `INPUT` / `FORWARD` / `OUTPUT` chains the way the flat iptables
  ruleset effectively does. ferm's base chains therefore coexist with
  other tables' base chains on the same hook (ordered by priority), so a
  packet may be accepted by a higher-priority foreign chain before
  reaching ferm's chain. A `policy DROP` in `table ip ferm` consequently
  behaves differently from iptables' monolithic `INPUT DROP`. This is the
  documented, expected behaviour of the own-table model, not a bug;
  admins who need the exact monolithic-DROP semantics should stay on the
  default `iptables` backend.

### Removed / not supported — Phase 2 (native nft backend)

- **`@preserve` is not supported by the `--nft` backend.** Using
  `@preserve` together with `--nft` is a clean, explicit error rather
  than a silent no-op. This is a deliberate, opt-in-backend regression;
  the default `iptables` backend supports `@preserve` exactly as before.

- **Port-bearing NAT requires a transport match under `--nft`.** A NAT
  verdict that maps a port (`DNAT to ...:port`, `SNAT to ...:port`,
  `REDIRECT`/`MASQUERADE to-ports`) with no preceding `proto tcp`/`udp`
  match is now a clean ferm error at translate time, because nft rejects
  such a mapping at apply (`transport protocol mapping is only valid after
  transport protocol match`) and would otherwise force a rollback. Add a
  protocol match to the rule.

### Security — Phase 2 (native nft backend)

- **`--nft` operands are escaped or validated before they reach the save
  script.** A config value carrying whitespace, `;`, `#`, or a double
  quote could previously break out of its nft token — for example
  `saddr "1.2.3.4 accept;#" DROP` rendered as
  `ip saddr 1.2.3.4 accept;# drop`, silently turning a `DROP` rule into
  `accept` (a form `nft -c` validates without complaint). Interface names
  are now emitted as escaped nft quoted strings (the `*` wildcard is
  preserved); addresses, ports, **protocols**, rate limits, and chain
  identifiers are grammar-validated, raising a plain ferm error rather
  than a ruleset nft would mis-apply. The protocol operand specifically
  (`proto "tcp accept;#" DROP` → `meta l4proto tcp accept;# drop`) was the
  last unguarded sink and is now validated like the others. The default
  `iptables` backend already escaped these operands and was never affected.
- **A failed rollback snapshot no longer degrades into a destructive
  delete.** The `--nft` rollback deletes ferm's own table when there is no
  previous snapshot (a genuine first run); a transient `nft list table`
  failure on an *existing* table is now distinguished from a real first run
  (by its non-`ENOENT` error) and aborts before any kernel change, instead
  of being mistaken for "no previous table" and deleting it on rollback.

### Fixed

- nft backend: render `reject-with tcp-reset` in the `ip6` family (it was
  only mapped for `ip`), matching the default backend and nftables' own
  family-agnostic `reject with tcp reset`.

### Changed

- `dnspython` is now an optional dependency (`pip install ferm[dns]`).
  Without it, `@resolve` uses the system stub resolver (`getaddrinfo`) and
  supports only `A`/`AAAA` records; `NS`/`MX` and other types raise a clear
  error. **Migration:** installs that relied on the previously-transitive
  `dnspython` get the stub backend after upgrading; reinstall with
  `ferm[dns]` to restore `NS`/`MX` support.

### Added — Phase 1 (faithful port)

- **Configuration language front end** ported from Perl: tokenizer and
  lazy token stream, the recursive-descent `enter()` parser over blocks,
  scopes and keywords, copy-on-write variable/function/array scoping, and
  deferred value realization (`@resolve()`, `@ipfilter()` and friends
  expand late).
- **Module-definition registry** and the compact option-encoding DSL
  (`add_proto_def` / `add_match_def` / `add_target_def` equivalents), so
  supported netfilter modules carry over from the Perl tables.
- **Rule assembly** — rule structure, unfolding into the cartesian product
  of option lists, `format_option` and byte-faithful `shell_escape`.
- **Per-family domains and the frozen `Options` model**, with the
  domains → backend injection seam.
- **iptables backend** with both execution paths: `--fast` (build a save
  file and pipe it to `iptables-restore`, atomic) and `--slow` (one
  `iptables` call per rule), plus `--shell` script emission.
- **CLI and top-level flow**, including `--noexec`, `--lines`,
  `--interactive` rollback with confirmation timeout, and the
  `ip` / `ip6` / `arp` / `eb` families.
- **`import-ferm`** — converts an `iptables-save` dump into a ferm
  configuration (save → ferm → save round-trip).
- **`@resolve` name resolver** backed by `dnspython`.

### Testing & tooling

- **Golden-file test harness** validated against the Perl oracle, with
  canonicalisation of the non-deterministic table/chain output order.
- **Differential fuzzing against the Perl oracle** (Hypothesis):
  tokenizer, `shell_escape`, import lexing, backtick splitting, `@substr`,
  option tokens, previous-state reader, and whole grammar-generated
  configs — driving fixes for `\s` Unicode handling (`re.ASCII`), Perl
  numification, the `substr`/undef model and byte-faithful save-dump
  regexes.
- **Real-world config corpus** compiled against the oracle (fast + slow).
- **`atheris` crash fuzzing** of both parsers and a **containerised
  anti-lockout e2e** for `--interactive` (both opt-in), plus a periodic
  **`mutmut` mutation** session.
- **Containerised data-plane e2e** (`nox -s datapath_e2e`, opt-in): drives
  real traffic with `nmap --reason` / `ncat` through ferm-installed rules
  across a three-netns topology, asserting ACCEPT / DROP / REJECT / state /
  NAT behaviour and parity between the `--nft` and default backends. An
  extensible distro matrix (`nox -s datapath_e2e_matrix`) reruns the same
  suite on Debian (bookworm + trixie), Ubuntu, Fedora, Arch, Rocky and
  openSUSE Leap, detecting the package manager (apt / dnf / apk / pacman /
  zypper) so adding a distro is a one-line entry.
- **Diagnostics parity** goldens pinning stderr for negative / params /
  warning cases.
- **Byte-faithful I/O**: config, backtick, zonefile and `--def` (`argv`)
  input read as latin-1 bytes and carried across the CLI, restore and
  `import-ferm` boundaries.
- **`MAX_BLOCK_DEPTH`** bound on parser block nesting and **`MAX_VALUE_DEPTH`**
  bound on value-reader nesting, both failing with a located diagnostic
  instead of a stack overflow.

### Project infrastructure

- Python project scaffolded at the repo root (`uv` + `src-layout`,
  `hatchling`), declaring support for Python **3.11–3.14**.
- The original Perl implementation relocated to `reference/` as the
  semantic oracle.
- `nox`-orchestrated gates (lint, tests, typecheck, coverage floor,
  matrix, fuzz, build, deps-lowest, workflow lint) wired into a binding
  `preflight` and into GitHub Actions CI (static checks split out, patch
  gate on PRs, weekly audit + Dependabot).

[Unreleased]: https://github.com/6RUN0/ferm/compare/py-v0.1.0a8...develop
[0.1.0a8]: https://github.com/6RUN0/ferm/compare/py-v0.1.0a7...py-v0.1.0a8
[0.1.0a7]: https://github.com/6RUN0/ferm/compare/py-v0.1.0a6...py-v0.1.0a7
[0.1.0a6]: https://github.com/6RUN0/ferm/compare/py-v0.1.0a3...py-v0.1.0a6
[0.1.0a3]: https://github.com/6RUN0/ferm/releases/tag/py-v0.1.0a3
