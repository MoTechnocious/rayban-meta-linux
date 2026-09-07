# Ray-Ban Meta Gen 2 - channel 7 handshake probe (option 1)
Date: 2026-09-07 · Device: RB Meta XXXX, BT <GLASSES_MAC> · Host: Linux (BlueZ)

## Verdict (the question option 1 was meant to settle)
The channel-7 handshake is **NOT hardware-anchored at the front door.** An
unpaired, unauthenticated, unknown host that merely speaks the protobuf format
correctly is driven through a full multi-round ECDH + AES-GCM key exchange. This
is the "obscure but reachable" bucket, not the "MFi-locked, impossible" one that
the previous recon feared. The MFi coprocessor seen on channel 4 is Apple iAP
for iPhones, a separate service; it does not gate channel 7.

## What was tested
All findings reproduced from scratch (no scripts survived the prior session).
Raw RFCOMM via Python AF_BLUETOOTH sockets; no sdptool/pybluez needed.

Channel map (direct connect scan, ch 1-12):
- ch 4  MFi/iAP hello, 6B  ff550200ee10
- ch 5  connect then reset (Spotify)
- ch 6  connect then reset (Amazon Music)
- ch 7  accepts unpaired host, sends 116B server hello (Meta control)

## The handshake
Server hello (msg1), 116B = 12B header + protobuf. 4 captures:
  header  807080018100000502000001  (identical every connection)
  field 1 64B  CHANGES every connect   -> ephemeral P-256 public key (raw X||Y)
  field 2 16B  CHANGES                  -> MAC / auth tag
  field 3 var 0    stable
  field 4 var 49   stable               -> version
  field 5 12B  CHANGES                  -> AES-GCM nonce (96-bit)
  field 7 var 23   stable               -> protocol version

Client hello sent back (msg2 test): 12B header + protobuf mirroring the same
shape, with a GENUINE P-256 ephemeral point we generated + our own random
nonce/tag. Result across trials:
  - valid ECDH client hello  -> server ADVANCES, replies 138B round-2   (repeatable)
  - 128B random garbage       -> no reply, socket held open idle
  - 12B header only           -> no reply, idle
  - no reply at all           -> no reply, idle (server waits)
So advancement is gated on STRUCTURAL/CRYPTO conformance, not on any secret.

Server round-2 (msg2), 138B = 8B header (8086000102000002) + protobuf:
  field 1 64B  CHANGES (3/3 runs distinct) -> server ephemeral public key
  field 2 32B                               -> encrypted blob or identity/sig share
  field 3 16B                               -> GCM tag
  field 4 var (large)                       -> session id / counter
  field 5 var 23 ; field 7 var 1 ; field 8 var 1

Round-3 wall probe: after a real round-2, send a bogus round-3.
  - bogus but structured msg3 -> server replies 25B, DIFFERENT every time
    (4/4 distinct) -> encrypted transport frame (nonce'd ciphertext), no reset
  - empty msg3 (header only)   -> no reply
=> transport encryption is established off the ECDH; post-round-2 traffic is AEAD.

## The remaining unknown (honest next wall)
Door is open; the open question moved from "can we talk to it" (YES, proven) to
"is the session key pure anonymous ECDH (software-reproducible) or does it fold
in a static device/Meta-app secret we cannot derive (authenticated-DH wall)?"
Prime suspect: round-2 field 2 (32B) as an encrypted certificate or SIGMA-style
identity proof. Next test: compute ECDH(our_priv, server_ephemeral), try common
KDFs (HKDF-SHA256), and check whether round-2's 16B tag verifies or the 25B
frame decrypts. If yes -> anonymous ECDH -> full software client is feasible. If
no -> authenticated DH -> we can be talked TO but cannot prove ourselves without
a device/app key -> that is the real (software, not hardware-extraction) wall.

## Scripts (in this folder)
  rfscan.py   channel scan
  cap.py      capture+decode server hello, ephemerality check
  probe7.py   5 client-hello trials
  probe7b.py  determinism + round-2 decode + bogus round-3
  probe7c.py  round-3 reply variance test

## Round 2 (decrypt attempt) - added same day
Follow-on to settle anonymous-ECDH vs device-secret-mixed.

Proven by black-box:
- Both server 64B fields (M1.field1, M2.field1) are VALID P-256 points -> genuine
  ECDH ephemerals, not random challenges.
- Real ECDH runs on OUR key: a valid client point yields the full 138B round-2;
  an off-curve 64B point yields only an 8B abort frame. The glasses consume our
  ephemeral as DH input.
- Round-2 payload = 32B ciphertext (field2) + 16B GCM tag (field3): AEAD transport
  is established off the exchange.
- Key derivation is NOT any of 4760 obvious constructions: SHA256/HKDF-SHA256 of
  the ECDH X-coord over {raw, sha256, hkdf16/32} x nonces {server, ours, zeros,
  counters} x AAD {none, header, empty, full-M1, serverpoint}, AES-128 and -256.
  No combination verified.

Interpretation (honest limit of black-box):
- The e / ee / s structure with protobuf framing looks like a CUSTOM Noise-style
  handshake (not raw Noise - it carries its own framing). In such a scheme the
  AEAD key comes from the full symmetric-state chain (mixHash of protocol-name +
  prologue + every framed message) and the AAD is the running transcript hash.
  A blind sweep cannot replicate that, so this NEGATIVE does not prove a device
  secret is required - it only rules out the naive constructions.
- Therefore the anonymous-vs-device-key question is NO LONGER answerable by
  black-box probing. It requires reading the construction from the Meta app's
  native crypto (the embedded Noise protocol-name string / KDF, and whether a
  static device or app key is mixed in).

## Where this leaves feasibility
- DOOR: open and reachable, not MFi-locked. (settled, high confidence)
- FULL INDEPENDENT SOFTWARE CLIENT: hinges on one well-defined reversing task
  (recover the KDF/transcript construction from the app binary). Until then it is
  "reachable protocol, key-derivation unknown", not proven either way.

## Two forward paths
A. Reverse the Meta View / Meta AI Android app native lib (static analysis) to
   recover the handshake construction. Only way to settle full-client feasibility.
   Research effort, uncertain payoff, but bounded and concrete.
B. Phone-relay bridge: a stripped app authenticates normally, forwards frames to
   this PC over plain Wi-Fi/RTSP. Sidesteps the protocol entirely. High confidence,
   but Meta software does the initial pairing.

## App-reversing phase - setup + a major side finding (same day)
Target app: **com.facebook.stella** (Meta AI app, formerly Meta View), the
Ray-Ban/Oakley glasses companion. Current builds ~v273. This is where the
channel-7 pairing + Noise handshake lives.

MAJOR side finding: Meta shipped an OFFICIAL **Wearables Device Access Toolkit**
(github.com/facebook/meta-wearables-dat-android, Maven com.meta.wearable:mwdat-*
v0.9.0, developer preview). It EXPOSES CAMERA VIDEO STREAMING + PHOTO CAPTURE to
a third-party app via a clean API (Wearables.createSession -> session.addCamera
-> camera.stream). BUT it delegates to the installed Meta AI app for
registration/permissions/pairing/firmware (changelog: dialogs jump to Meta AI
app; openFirmwareUpdate/openDATGlassesAppUpdate target "Meta AI"). So:
  - the SDK is a thin client; the companion app holds the glasses link + crypto
  - => confirms com.facebook.stella is the correct reversing target
  - => there is now a SANCTIONED path to camera frames in your own Android app,
       phone- and Meta-AI-app-mediated, developer-preview, org registration gated.
Practical implication: the realistic "frames on PC" route is a tiny Android app
using mwdat-camera that forwards camera.stream to the PC over Wi-Fi (sanctioned
version of the relay bridge), UNLESS the fully-independent no-Meta-software
client proves feasible from the reverse below.

Tooling staged locally: jadx 1.5.6 (DEX), binutils strings/readelf/objdump
(native .so). APK acquisition in progress.

## VERDICT from the binary reverse (com.facebook.stella v287.1.0.14.153)
Two distinct secure layers confirmed in the native libs + DEX:

1. Oxide AI transport: **Noise_XX_25519_AESGCM_SHA256** via Rust `snow` 0.10
   (libxplat_oxide_extensions_hatch_noise_oxide-noise). Higher-level AI/data path.
2. Channel-7 BLE control (what black-box probed): a CUSTOM, certificate-anchored,
   authenticated **P-256 ECDH** handshake done Java-side via Android JCA
   KeyAgreement ("computeSharedSecret", "KeyAgreement for algorithm ECDH"),
   protobuf-framed (wearable_pb_impl_service, pairing_messages).

Trust model (the wall):
- Glasses hold a **Device Root Key (DRK)** whose X.509 cert chains to
  **"Facebook Rootcanal Prod Root CA"** (Facebook Inc, 2018-2048), embedded in
  the app together with "Facebook Production CA 2017 Q4". Handshake carries
  attestationCertChain / DRK_CERTIFICATE_PRESENT / includeAttestationBundles.
- Challenge-response: txChallenge ("No tx challenge! Cannot authenticate"),
  registrationChallengeRequestPackage, PendingEncryptionValues(txChallenge=...).
- Companion identity is **FETCHED from Meta**, not minted locally:
  request_sent_to_fetch_companion_ephemeral_identity, companionEphIdentity
  request can fail; app registers via **/wearable/acdc/AppRegisterRequest**
  (ACDCService) and a backend session at **https://ember.wearables-ape.io**.
- BLE bonding + pairing mode also present: REQUEST_PERIPHERAL_ENABLEPAIRINGMODE,
  RECEIVED_PERIPHERAL_PAIRINGMODEREADY, onBondEstablished, "Ithaca on-device
  pairing", Auto-Accept-Pairing disabled by default (user-confirmed).

## Bottom line on a fully independent (no-Meta-software) client
NOT feasible by protocol reimplementation alone. The channel-7 handshake is
REACHABLE (black-box proved that) but completing it as an ACCEPTED companion is
mutual, certificate/identity-anchored auth: the glasses prove themselves via a
Meta-CA-rooted DRK cert, and the companion must present an identity that appears
to be provisioned through a Meta account/backend (companionEphemeralIdentity
fetch + ACDC AppRegister + attestation). You cannot forge a companion identity
the glasses will trust without Meta's PKI/account cooperation.

Single remaining uncertainty: whether the INITIAL on-device pairing ceremony
(physical possession + pairing mode) registers a LOCALLY-generated companion key
without a server-side attestation check. If it does, an independent client is
possible for someone with physical control at pairing time; the fetched
companionEphIdentity + attestation bundles suggest pairing likely still calls
home. Settling this needs DYNAMIC analysis (instrument a live pairing) or deep
decompile of the ACDC AppRegister + companionEphIdentity flow.

## Recommended route to "camera frames on PC" given the above
The sanctioned Meta Wearables Device Access Toolkit (mwdat-camera) is now the
realistic path: a small Android app receives camera.stream and forwards frames
to the PC over Wi-Fi. It rides Meta's authenticated companion session (which is
exactly the wall above), so it sidesteps reimplementing any of this. Cost:
Android phone in the loop + Meta AI app + developer-preview org registration.

## LAST GAP CLOSED - static flow analysis of pairing/provisioning
Decompiled com.facebook.stella v287 (jadx) and traced the pairing path.
Answer: initial pairing REQUIRES Meta's servers. Not local/offline/TOFU.

Concrete proof from decompiled code (Redex-obfuscated but the crypto/network
call sites are readable):
- AttestationUtil.attestApplication (silverstone/deviceaccesstoolkit) issues a
  GraphQL mutation to Meta's backend:
    op = "WearablesAndroidAttestationMutation"
    persisted id = "xar_wearables_dat_android_attest"
    inputs = package_name, certificate_chain, attestation_session_id
    returns Boolean pass/fail
  => server-side app-authenticity attestation. A non-genuine app/package fails
     here -> InauthenticAppException / InauthenticDeviceException.
- Ownership provisioning ("enableTrust") lives in connectivity.security.ownership
  whose exception set includes NoInternetException, ServerException,
  UnownedDeviceException, WrongOwnerException, ReprovisionException,
  ProvisioningTimeoutException => online, account-tied ownership.
- companion identity + integration/attestation bundles are FETCHED from Meta
  (xar_wearables_integration_bundles_v, companionEphemeralIdentity request).
- app<->glasses binding registered via /wearable/acdc/registrar (+ /acdc/sdk).
- Only a separate PrototypeIdentity / prototype-authentication path uses local
  identity, and that is for Meta internal prototype hardware, not retail units.

CONCLUSION (final): a fully independent, no-Meta-software client CANNOT pair
retail Ray-Ban Meta glasses. The wall is a server-side app attestation +
account-tied ownership provisioning, not the on-device handshake. Credential
reuse (extracting provisioned keys from a genuinely-paired rooted phone) is the
only theoretical bypass, and that is credential theft from a real install, not
an independent implementation.

Live confirmation kit provided in live-confirmation-kit/ (airplane-mode test +
Frida trace) so the user can independently verify on their own phone.
