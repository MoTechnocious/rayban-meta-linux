# Live-confirmation kit - does pairing need Meta's servers?

Static decompilation already answered YES (see FINDINGS "LAST GAP CLOSED").
These let you verify it live on your own phone.

## Quickest (no root, no tooling): 01_airplane_mode_test.md
Put the phone offline and try to pair. It should fail. Done.

## Detailed (rooted phone / emulator): frida_pairing_trace.js
Watch the exact GraphQL ops and crypto calls during a pairing:
- expect [GQL] WearablesAndroidAttestationMutation before pairing completes
- with the phone offline, expect [EXC] NoInternetException on the provisioning path
- [KA] KeyAgreement.generateSecret marks the channel-7 P-256 ECDH
Needs frida-server on a rooted device (or a Frida-gadget-repacked APK). Setup:
  https://frida.re/docs/android/

## What a confirming result looks like
Offline pairing fails + (with Frida) NoInternetException on the ownership flow,
and/or WearablesAndroidAttestationMutation never returns => pairing is
server-gated, matching the static finding. An independent no-Meta-software
client cannot reproduce this.
