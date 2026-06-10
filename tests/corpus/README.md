# Real-world ferm config corpus

Configurations collected from public repositories (fetched 2026-06-10)
and compiled by both the frozen Perl oracle and the Python port; see
`test_corpus.py` for the comparison contract.  They are included solely
for interoperability testing of this port against real-world usage; each
file remains under its source repository's terms.

The upstream examples (`reference/examples/*.ferm`) are part of the same
suite but are run in place, except `resolve.ferm`, which is copied here
as `upstream-resolve.ferm` so its mock DNS `zonefile` can live next to
it.

## Sanitization

Every edit made to a fetched file is marked inline with a
`[corpus: ...]` comment:

* `@include` lines are commented out (the included files are not part of
  the corpus) and variables they were supposed to define are stubbed
  with documentation-range addresses;
* backtick command substitutions are replaced with literal values (ferm
  executes backticks even under `--noexec`);
* one syntax error in an editor-plugin example (`@def &func(...) {`
  missing its `=`) is fixed so the file exercises rule emission.

Template files (Jinja2/ERB `ferm.conf` templates) were rejected during
collection.

## Sources

| corpus file | repository | path |
| `americancouncils.ferm` | [AmericanCouncils/ac-common-ansible](https://github.com/AmericanCouncils/ac-common-ansible) | `files/ferm.conf` |
| `anxs-the-ansibles.ferm` | [ANXS/the-ansibles](https://github.com/ANXS/the-ansibles) | `roles/firewall/files/etc_ferm_ferm.conf` |
| `aur3-mirror.ferm` | [felixonmars/aur3-mirror](https://github.com/felixonmars/aur3-mirror) | `ferm/ferm.conf` |
| `blinken-paradar.ferm` | [blinken/paradar](https://github.com/blinken/paradar) | `deploy/system/etc.ferm.conf` |
| `brutesque-out.ferm` | [brutesque/docker-swarm-over-vpn-mesh](https://github.com/brutesque/docker-swarm-over-vpn-mesh) | `roles/setup_ubuntu/files/01-out.oracle_provided.ferm` |
| `brutesque-swarm.ferm` | [brutesque/docker-swarm-over-vpn-mesh](https://github.com/brutesque/docker-swarm-over-vpn-mesh) | `roles/setup_ubuntu/files/ferm.conf` |
| `dcent-stonecutter.ferm` | [d-cent/stonecutter](https://github.com/d-cent/stonecutter) | `ops/roles/ferm/files/ferm.conf` |
| `epitron-scripts.ferm` | [epitron/scripts](https://github.com/epitron/scripts) | `etc/ferm.conf` |
| `ferm-tools-example.ferm` | [ruslanfialkovskii/ferm-tools.nvim](https://github.com/ruslanfialkovskii/ferm-tools.nvim) | `test/example.ferm` |
| `ffda-gateway.ferm` | [freifunk-darmstadt/ffda-gateway-config](https://github.com/freifunk-darmstadt/ffda-gateway-config) | `ferm/ferm.conf` |
| `grnet-synnefo.ferm` | [grnet/synnefo](https://github.com/grnet/synnefo) | `snf-deploy/files/etc/ferm/ferm.conf` |
| `himdel-dotfiles.ferm` | [himdel/dotfiles](https://github.com/himdel/dotfiles) | `etc/ferm/ferm.conf` |
| `meetings-devops.ferm` | [meetings/devops](https://github.com/meetings/devops) | `roles/ferm/files/ferm.conf` |
| `netheads-server.ferm` | [netheads/server](https://github.com/netheads/server) | `ferm.conf` |
| `ngxirc-ngxbot-host.ferm` | [ngxirc/ngxbot-host](https://github.com/ngxirc/ngxbot-host) | `states/ferm/ferm.conf` |
| `objective8.ferm` | [ThoughtWorksInc/objective8](https://github.com/ThoughtWorksInc/objective8) | `ops/roles/ferm/files/ferm.conf` |
| `pgapt-jenkins.ferm` | [d/pgapt](https://github.com/d/pgapt) | `jenkins/ansible/ferm.conf` |
| `revolucaodosbytes.ferm` | [revolucaodosbytes/ansible](https://github.com/revolucaodosbytes/ansible) | `roles/ferm/files/ferm.conf` |
| `rootnode-lxc.ferm` | [lukaszx0/rootnode-legacy](https://github.com/lukaszx0/rootnode-legacy) | `lxc/ferm/ferm.conf` |
| `rwthctf2012-vpn.ferm` | [oldeurope/rwthctf2012](https://github.com/oldeurope/rwthctf2012) | `vpn/ferm.conf` |
| `stuart-ha-bedroom.ferm` | [stuart12/stuart-system](https://github.com/stuart12/stuart-system) | `home-automation/home-assistant/bedroom/firewall.ferm` |
| `stuart-ha-server.ferm` | [stuart12/stuart-system](https://github.com/stuart12/stuart-system) | `home-automation/home-assistant/server/firewall.ferm` |
| `tapirgo-common.ferm` | [TapirGo/ansible](https://github.com/TapirGo/ansible) | `roles/common/templates/etc/ferm/ferm.conf` |
| `thewirl-personal-distro.ferm` | [thewirl/personal-distro](https://github.com/thewirl/personal-distro) | `ferm.conf` |
| `thexhr-config.ferm` | [thexhr/config](https://github.com/thexhr/config) | `etc/ferm.conf` |
| `unexicon.ferm` | [bbidulock/unexicon-system](https://github.com/bbidulock/unexicon-system) | `unexicon.ferm` |
| `vpngw-gw.ferm` | [ThomasWaldmann/vpngw](https://github.com/ThomasWaldmann/vpngw) | `gw/etc/ferm/ferm.conf` |
| `wuvt-router.ferm` | [wuvt/wuvt-ansible](https://github.com/wuvt/wuvt-ansible) | `roles/router/files/ferm/ferm.conf` |
| `upstream-resolve.ferm` | ferm upstream | `examples/resolve.ferm` |
