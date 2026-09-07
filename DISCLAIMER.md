# Disclaimer and scope

This project is independent interoperability and security research. It is not
affiliated with, endorsed by, or connected to Meta Platforms, Inc. "Ray-Ban" is
a trademark of Luxottica; "Meta" is a trademark of Meta Platforms, Inc. Names are
used only to identify the hardware under study.

## What is NOT included

To respect copyright and Meta's intellectual property, this repository contains
**none** of the following, and never will:

- The Meta AI / Meta View application (`com.facebook.stella`) or any part of it.
- Any decompiled source, native libraries (`.so`), or DEX extracted from it.
- Any cryptographic keys, certificates, or certificate chains from the app or
  the glasses.
- Any credential, token, or provisioning material.

The research files describe **observed behaviour** and name public protocol
constructs (e.g. a Noise protocol-name string, GraphQL operation names). They do
not reproduce Meta's code or secrets.

## What this project deliberately does not do

The findings conclude that the pairing/provisioning is anchored in Meta's PKI and
account system and **cannot** be bypassed by reimplementing the protocol. This
repository provides no bypass, no attestation forgery, and no method to spoof an
authorised companion. It documents why such a thing is not feasible.

## Intended use

- Using the glasses as a standard Bluetooth audio device on Linux.
- Recovering a Bluetooth connection after a factory reset.
- Understanding the device's security architecture.

Only use the tools here against hardware you own. You are responsible for
complying with your local laws and with Meta's terms of service.

## Warranty

Provided "as is", without warranty of any kind. Bluetooth stacks and firmware
differ; the pairing helper may need adjustment for your setup.
