/*
 * Frida trace for Meta AI (com.facebook.stella) pairing/provisioning.
 * Proves whether pairing hits Meta's servers and whether the companion key is
 * generated locally. Attach during a fresh pairing.
 *
 * Run (rooted phone or emulator with frida-server, or a Frida-gadget repack):
 *   frida -U -f com.facebook.stella -l frida_pairing_trace.js --no-pause
 * or attach:
 *   frida -U -n "Meta AI" -l frida_pairing_trace.js
 *
 * Then perform a pairing in the app and read the log. Key things to watch:
 *  [GQL]  WearablesAndroidAttestationMutation  -> server app-attestation fired
 *  [GQL]  ...ownership / provisioning ops       -> server provisioning
 *  [EXC]  NoInternetException / InauthenticApp   -> which gate failed (try offline)
 *  [KEY]  KeyPairGenerator.generateKeyPair       -> a local key IS generated
 *  [KA]   KeyAgreement.generateSecret            -> the P-256 ECDH (channel 7)
 */
Java.perform(function () {
  function stack() {
    return Java.use("android.util.Log").getStackTraceString(
      Java.use("java.lang.Exception").$new());
  }

  // 1) GraphQL operations (Meta Pando client) - logs every op name sent
  try {
    var Pando = Java.use("com.facebook.pando.PandoGraphQLRequest");
    Pando.$init.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try {
          for (var i = 0; i < arguments.length; i++) {
            var a = arguments[i];
            if (a && typeof a === "string" &&
                (a.indexOf("Wearable") >= 0 || a.indexOf("wearable") >= 0 ||
                 a.indexOf("xar_") === 0 || a.indexOf("ttestation") >= 0 ||
                 a.indexOf("rovision") >= 0 || a.indexOf("wnership") >= 0)) {
              console.log("[GQL] op/param: " + a);
            }
          }
        } catch (e) {}
        return ov.apply(this, arguments);
      };
    });
    console.log("[hook] PandoGraphQLRequest constructors hooked");
  } catch (e) { console.log("[hook] Pando not found: " + e); }

  // 2) Ownership/provisioning exceptions - shows which server gate fails offline
  var excPkg = "com.facebook.wearable.companion.connectivity.security.ownership.";
  ["NoInternetException","ServerException","InauthenticAppException",
   "InauthenticDeviceException","UnownedDeviceException","WrongOwnerException",
   "IdentityMissingException","EnableTrustException","ReprovisionException",
   "ProvisioningTimeoutException"].forEach(function (name) {
    try {
      var C = Java.use(excPkg + name);
      C.$init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          console.log("[EXC] " + name + " thrown\n" + stack());
          return ov.apply(this, arguments);
        };
      });
    } catch (e) {}
  });
  console.log("[hook] ownership exceptions hooked");

  // 3) Local key generation + the P-256 ECDH (JCA)
  try {
    var KPG = Java.use("java.security.KeyPairGenerator");
    KPG.generateKeyPair.implementation = function () {
      console.log("[KEY] KeyPairGenerator.generateKeyPair (algo=" +
                  this.getAlgorithm() + ")\n" + stack());
      return this.generateKeyPair();
    };
  } catch (e) {}
  try {
    var KA = Java.use("javax.crypto.KeyAgreement");
    KA.generateSecret.overload().implementation = function () {
      console.log("[KA] KeyAgreement.generateSecret (algo=" +
                  this.getAlgorithm() + ") - channel-7 ECDH\n" + stack());
      return this.generateSecret();
    };
  } catch (e) {}
  try {
    var AU = Java.use("com.facebook.wearable.companion.silverstone.deviceaccesstoolkit.utils.AttestationUtil");
    console.log("[hook] AttestationUtil present: " + AU);
  } catch (e) {}
  console.log("[ready] pair the glasses now and watch the log");
});
