# Live confirmation #1 - the airplane-mode pairing test (no root, no tooling)

This is the simplest conclusive test of "does pairing need Meta's servers?".

Preconditions:
- The glasses are FACTORY RESET / unpaired (so a fresh pairing is required).
  (On a paired pair, do Settings -> forget device first. Note: resetting
  requires you to re-pair afterward, so only do this if you are willing to.)
- A phone with the Meta AI app installed but NOT yet paired to these glasses.

Test:
1. Put the phone in AIRPLANE MODE (Wi-Fi + mobile data OFF). Bluetooth ON.
2. Put the glasses into pairing mode.
3. In the Meta AI app, attempt to add/pair the glasses.

Expected results and what they prove:
- If pairing FAILS with a "no connection / try again / can't reach Meta" style
  error and never completes -> pairing REQUIRES Meta's servers (confirms the
  static finding: WearablesAndroidAttestationMutation + ownership provisioning).
- If pairing COMPLETES fully offline and the glasses then work -> pairing is
  local; the static finding would be wrong (not expected).

The code path predicts the first outcome: NoInternetException in the ownership
provisioning flow, and the attestation GraphQL mutation cannot be sent offline.
