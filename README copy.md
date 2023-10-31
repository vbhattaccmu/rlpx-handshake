## Problem statement

Reimplement RLPx protocol in Rust. Refactored [the original implementation](https://github.com/vorot93/devp2p) as it does not build with recent updates from secp256k1 crate .

## Technical Goals

The implementation focusses on following:-

1. Simplifying MAC egress/ingress validation.
2. Simplifying transport layer and codec definitions.
3. Updating secp256k1 crates to its latest version and its function signatures.
4. Adding handshake tests to make sure it communicates with latest geth client.

## Hard Requirements

- The solution has to perform a full **protocol-level** (post-TCP/etc.) handshake with the target node.

## Solution

The repository consists of a geth client which can spin up a local network in your machine. The other crate is a lightweight client performing
the handshake with the geth client.

The handhake occurs in two phases:-

Phase I - Send auth and receive ack to/from recipient

Phase II - Send/Recv outbound message to/from recipient

The formulation for Phase I and II are adapted from source [RLPx protocol](https://hackmd.io/@Nhlanhla/SJv3wnhMK)

### Phase I

Phase I is implemented by using a state machine to decode incoming data via codec and transition between different states of the handshake between peers.The implementation can be found in `server/networking/codec.rs`

The initial auth-ack handshake from [source](https://hackmd.io/@Nhlanhla/SJv3wnhMK) is defined as follows:-

```
auth = auth-size || enc-auth-body
auth-size = size of enc-auth-body, encoded as a big-endian 16-bit integer
auth-body = [sig, initiator-pubk, initiator-nonce...]
enc-auth-body = codec.encrypt(recipient-pubk, auth-body || auth-padding, auth-size)

ack = ack-size || enc-ack-body
ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
ack-body = [recipient-ephemeral-pubk, recipient-nonce,...]
enc-ack-body = codec.encrypt(initiator-pubk, ack-body || ack-padding, ack-size)
```

### Other cryptographic exhanges taking place in Phase I

1. Secrets generated following the exchange of auth-ack handshake messages.
   ```
   ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
   shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
   aes-secret = keccak256(ephemeral-key || shared-secret)
   mac-secret = keccak256(ephemeral-key || aes-secret)
   ```
2. MAC: Message Authentication Code from initiator
   ```
   ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
   ```
   ingress mac is checked against mac bytes received from the header and body.

### Phase II

After the auth-ack phase is complete an outbound message is sent to the recipient and it sends
back a response which is deserialized back.

## Prerequisites

The following service utilizes docker

- cargo: compiler for Rust.
  To install Rust you will need the following command.This will install rustup as well.
  ```
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  ```
- gcc: required for libc bindings
  See [here](https://phoenixnap.com/kb/install-gcc-ubuntu) for installation options.

- docker and its utilities
  User requires to install Docker and Docker Compose(v2) on their machine. See [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

  The following are the versions of the toolchain

  | Toolchain      | Version                       |
  | :------------- | :---------------------------- |
  | Ubuntu         | 22.04.3 LTS                   |
  | cargo          | 1.72.0 (103a7ff2e 2023-08-15) |
  | rustup         | 1.26.0                        |
  | gcc            | 11.4.0                        |
  | docker         | 24.0.5 build ced0996          |
  | docker compose | v2.20.0                       |

## How to execute

1. Enable permissions on the run.sh file by performing
   ```
   chmod +x run.sh
   ```
2. Run run.sh file. You will be prompted to enter your password because docker compose needs to be run with
   admin privileges. You will get the following output.

   ```
   ./run.sh
   ```

   Output:-

   ```
    [+] Running 4/4
    ✔ Network geth_priv-eth-net           Crea...                             0.2s
    ✔ Container geth-geth-bootnode-1      Started                             1.0s
    ✔ Container geth-geth-rpc-endpoint-1  Started                             1.8s
    ✔ Container geth-geth-miner-1         St...                               1.6s
        Finished test [unoptimized + debuginfo] target(s) in 0.08s
        Running unittests src/lib.rs (target/debug/deps/rlpx_handshake-31be7cfd58185a34)

    running 2 tests
    test tests::test_handshake_failure_with_incorrect_id ... ok
    test tests::test_handshake_success ... ok

    test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
   ```

3. Please run the `cleanup.sh` command in order to clean up artifacts to save resources.
   ```
   ./cleanup.sh
   ```

## How to know if handshake is successful

The only way to know if the handshake is successful is

1. To check if the geth recipient node sends back its client version and its current protocol version at the end of the
   handshake in Phase II after the initiator sends a `Hello` frame with its own client and protocol version.

   In this case the recipient client version: `Geth/v1.10.1-stable-c2d2f4ed/linux-amd64/go1.16`
   and the protocol version is `5`.

2. To check if the the handshake fails when we use a different public key other than the actual node public key.

   In this case the node public key defined in docker compose setupfor geth node:
   `af22c29c316ad069cf48a09a4ad5cf04a251b411e45098888d114c6dd7f489a13786620d5953738762afa13711d4ffb3b19aa5de772d8af72f851f7e9c5b164a`

Two `tests test tests::test_handshake_failure_with_incorrect_id` and `test tests::test_handshake_success` are defined two test (1) and (2).
