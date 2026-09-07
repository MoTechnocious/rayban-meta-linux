# rayban-meta-linux

Using **Ray-Ban Meta (Gen 2)** smart glasses on Linux, plus an honest
reverse-engineering study of their Bluetooth control channel.

Two things live here:

1. **A practical Linux pairing helper** ([`linux-pairing/`](linux-pairing/)) to
   use the glasses as a Bluetooth audio device and to recover the connection
   after a factory reset. This is the part most people want.
2. **Protocol research** ([`research/`](research/)) documenting what the glasses
   expose over Bluetooth RFCOMM, and why building a fully independent, no-Meta
   client is not viable. Black-box probes plus a static read of the companion
   app's own crypto choices.

> No Meta application code, binaries, keys, or certificates are included or
> redistributed. See [DISCLAIMER.md](DISCLAIMER.md). All work was done on the
> author's own hardware for interoperability and security research.

## TL;DR findings

- The glasses pair to a Linux PC as a normal Bluetooth audio device (A2DP + HFP).
  A factory reset invalidates the PC's stored bond; re-pairing fixes it.
- Over Bluetooth Classic RFCOMM the glasses expose vendor channels. One control
  channel accepts an unpaired host and runs an **authenticated P-256 ECDH +
  AES-GCM** handshake wrapped in protobuf. The link is *reachable*, but becoming
  an accepted companion is **not**.
- The companion app additionally uses a textbook Noise handshake
  (`Noise_XX_25519_AESGCM_SHA256`, via the Rust `snow` library) for its higher
  AI transport.
- **Pairing is gated by Meta's servers**: a server-side app-authenticity
  attestation (an Android key-attestation certificate chain checked by a Meta
  GraphQL endpoint) plus account-tied ownership provisioning. A locally
  generated key cannot be registered offline. So an independent no-Meta-software
  client cannot pair retail glasses; the wall is Meta's PKI/account system, not
  the on-device handshake.
- The realistic route to camera frames on a PC is Meta's official **Wearables
  Device Access Toolkit** (`mwdat-camera`) in a phone app that forwards the
  stream over Wi-Fi. Phone- and Meta-app-mediated, developer preview.

Full write-up: [research/channel7-findings.md](research/channel7-findings.md).

## Layout

```
linux-pairing/           pair-glasses.sh + guide (audio use, reset recovery)
research/
  channel7-findings.md   the full reverse-engineering write-up
  tools/                 black-box probe scripts (raw RFCOMM, no attack code)
live-confirmation-kit/   optional tests that confirm pairing needs Meta's servers
```

## Research tools

Pure-Python RFCOMM probes using `AF_BLUETOOTH` sockets (no pybluez). They open a
vendor channel, read the handshake, and parse the protobuf. They contain no
exploit and cannot bypass anything; they characterise observable behaviour.
Point them at your own glasses:

```
pip install cryptography
GLASSES_MAC=98:59:49:AA:BB:CC python3 research/tools/rfscan.py 1 12
GLASSES_MAC=98:59:49:AA:BB:CC python3 research/tools/capture-handshake.py
```

## Status

Research complete. Contributions and corrections welcome, especially from other
Meta wearables or other Linux setups. Please keep the no-redistribution rule in
[DISCLAIMER.md](DISCLAIMER.md).

## License

[MIT](LICENSE).
