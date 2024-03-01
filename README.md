# Bitcoin Events Plugin

This repository contains the `bitcoin` plugin for `Falco`, it subscribes to the websocket feed `wss://ws.blockchain.info/inv` to receive the latest transactions.

> [!WARNING]  
> This plugin has been created to demonstrate the power of `Falco` and its plugins to ingest any kind of streamed events and apply rules over them.

- [Bitcoin Events Plugin](#bitcoin-events-plugin)
- [Event Source](#event-source)
- [Supported Fields](#supported-fields)
- [Development](#development)
  - [Requirements](#requirements)
  - [Build](#build)
- [Installation](#installation)
  - [Requirements](#requirements-1)
  - [Local](#local)
  - [With falcoctl](#with-falcoctl)
  - [With Helm](#with-helm)
- [Settings](#settings)
- [Rules](#rules)
  - [Results](#results)

# Event Source

The event source for `bitcoin` events is `bitcoin`.

# Supported Fields

|        Name        |  Type  |                       Description                       |
| ------------------ | ------ | ------------------------------------------------------- |
| `btc.time`         | uint64 | Time                                                    |
| `btc.wallet`       | string | Wallet                                                  |
| `btc.hash`         | string | Hash                                                    |
| `btc.amount`       | string | Amount (in BTC)                                         |
| `btc.amount_sats`  | string | Amount (in SATS), can be used with `>`, `<` comparators |
| `btc.relayedby`    | string | Relayed y                                               |
| `btc.transaction`  | string | Type of the transaction (`sent` or `received`)          |
| `btc.destinations` | list   | List of targets for the `sent` transactions             |
| `btc.sources`      | list   | List of sources for the `received` transactions         |

# Development
## Requirements

You need:
* `Go` >= 1.19

## Build

```shell
make build
```

# Installation

## Requirements

* `Falco` >= 0.36

## Local

* Build and install the plugin:
  ```shell
  git clone https://github.com/Issif/bitcoin-plugin.git
  cd bitcoin-plugin
  make install
  ```
* Configure `Falco` with the `/etc/falco/falco.yaml` file:
  ```yaml
  plugins:
    - name: bitcoin
      library_path: /usr/share/falco/plugins/libbitcoin.so
      init_config: ''
      open_params: ''

  load_plugins: [bitcoin]

  stdout_output:
    enabled: true
  ```
* Run `Falco`:
  ```shell
  falco -c /etc/falco/falco.yaml -r rules/bitcoin_rules.yaml --disable-source syscall
  ```

## With falcoctl

* Add the index:
  ```shell
  sudo falcoctl index add bitcoin https://raw.githubusercontent.com/Issif/bitcoin-plugin/workflow/index.yaml
  ```
* Search for the artifacts:
  ```shell
  sudo falcoctl artifact search bitcoin
  ```
  ```shell
  INDEX   ARTIFACT        TYPE            REGISTRY        REPOSITORY                              
  bitcoin  bitcoin-rules    rulesfile       ghcr.io         issif/bitcoin-plugin/ruleset/bitcoin-rules
  bitcoin  bitcoin          plugin          ghcr.io         issif/bitcoin-plugin/plugin/bitcoin 
  ```
* Install the plugin and the rules:
  ```shell
  sudo falcoctl artifact install bitcoin-rules:latest
  ```
  ```shell
  INFO  Reading all configured index files from "/root/.config/falcoctl/indexes.yaml"
  INFO  Resolving dependencies ...
  INFO  Installing the following artifacts: [ghcr.io/issif/bitcoin-plugin/ruleset/bitcoin:latest]
  INFO  Preparing to pull "ghcr.io/issif/bitcoin-plugin/ruleset/bitcoin:latest"
  INFO  Pulling c09e07b53699: ############################################# 100% 
  INFO  Pulling 1be5f42ebc40: ############################################# 100% 
  INFO  Pulling 751af53627f8: ############################################# 100% 
  INFO  Artifact successfully installed in "/etc/falco"  
  ```
* Run `Falco`:
  ```shell
  falco -c /etc/falco/falco.yaml -r /etc/falco/bitcoin_rules.yaml --disable-source syscall
  ```

## With Helm

* Edit the `values.yam`:
  ```yaml
  tty: true
  kubernetes: false

  falco:
    rules_file:
      - /etc/falco/bitcoin_rules.yaml
    plugins:
    - name: bitcoin
      library_path: libbitcoin.so
    load_plugins: [bitcoin]

  driver:
    enabled: false
  collectors:
    enabled: false

  controller:
    kind: deployment
    deployment:
      replicas: 1

  falcoctl:
    config:
      indexes:
        - name: bitcoin
          url: https://raw.githubusercontent.com/Issif/bitcoin-plugin/main/index.yaml
      artifact:
        install:
          refs: ["bitcoin:0"]
        follow:
          refs: ["bitcoin-rules:0"]
  ```
  * Deploy `Falco`:
  ```shell
  helm install falco-bitcoin -n falco falcosecurity/falco -f values.yaml
  ```

# Settings

n/a

# Rules

A default `rules.yaml` file is provided.

The `source` for rules must be `bitcoin`.

See example:
```yaml
- rule: New Sent transaction
  desc: Denug
  condition: btc.transaction="sent"
  output: The wallet %btc.wallet sent %btc.amount BTC to %btc.destinations in the transaction %btc.hash 
  priority: INFORMATIONAL
  source: bitcoin
  tags: [bitcoin]

- rule: New Received transaction
  desc: Denug
  condition: btc.transaction="received"
  output: The wallet %btc.wallet received %btc.amount BTC from %btc.sources in the transaction %btc.hash 
  priority: INFORMATIONAL
  source: bitcoin
  tags: [bitcoin]

```

## Results

```shell
2024-02-20T13:24:45.686652000+0000: Informational The wallet bc1q28gqnp6fdxdsfjr0ddpmp9ah05awadq7tcrsre received 0.000094024 BTC from (bc1q80cdne2eqw0y778fh4g5p7s7v4jk23l94q38rd) in the transaction f6cc0969fd63479b1926fabe7691544ed69fa7f77dea7e0cc001cb1815579720
2024-02-20T13:24:45.686698000+0000: Informational The wallet bc1qn2galc22rz29nsme9tfmjec9vaq6sqa3lmmfwe sent 0.009396256 BTC to (14Ad6DYi7Kb3yDNyhfwb9Cb47bcV56ESQH,bc1qn2galc22rz29nsme9tfmjec9vaq6sqa3lmmfwe) in the transaction ab20978445c0b0a23d8c163701d3a7128d1dd978385bb0a6e5ffe56a8140d532
2024-02-20T13:24:45.686739000+0000: Informational The wallet 14Ad6DYi7Kb3yDNyhfwb9Cb47bcV56ESQH received 0.001900000 BTC from (bc1qn2galc22rz29nsme9tfmjec9vaq6sqa3lmmfwe) in the transaction ab20978445c0b0a23d8c163701d3a7128d1dd978385bb0a6e5ffe56a8140d532
2024-02-20T13:24:45.686786000+0000: Informational The wallet bc1qn2galc22rz29nsme9tfmjec9vaq6sqa3lmmfwe received 0.007492656 BTC from (bc1qn2galc22rz29nsme9tfmjec9vaq6sqa3lmmfwe) in the transaction ab20978445c0b0a23d8c163701d3a7128d1dd978385bb0a6e5ffe56a8140d532
```