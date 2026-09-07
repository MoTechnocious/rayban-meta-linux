# Using Ray-Ban Meta (Gen 2) glasses on Linux

The glasses work as a standard Bluetooth audio device (open-ear headphones +
headset mic) on Linux via BlueZ, independently of the phone companion app. This
folder has a helper that pairs them and, importantly, recovers the connection
after a **factory reset**, which invalidates any previous bond stored on the PC.

## Pair or re-pair

1. Put the glasses in **Bluetooth pairing mode**: place them in the charging
   case, open the lid, and hold the pairing button inside the case until the LED
   blinks. The Meta AI app has no separate "connect a device" option; the in-case
   button is the intended method.
2. Find the MAC:
   ```
   bluetoothctl scan on      # look for "RB Meta ...." on a 98:59:49:... address
   ```
3. Run the helper:
   ```
   GLASSES_MAC=98:59:49:AA:BB:CC ./pair-glasses.sh
   ```
4. Take the glasses **out of the case** and power them on. They will reconnect
   automatically (they are marked Trusted).

## After a factory reset

A reset regenerates the glasses' pairing keys, so the PC's old bond is stale and
reconnection fails with `br-connection-canceled` / "terminated by remote user".
The helper handles this by removing the stale bond first, then pairing fresh.
You can also do it by hand:

```
bluetoothctl remove 98:59:49:AA:BB:CC     # drop the stale bond
# put glasses in pairing mode (in case, hold button)
bluetoothctl
  agent off
  agent NoInputNoOutput
  default-agent
  scan on
  pair 98:59:49:AA:BB:CC
  trust 98:59:49:AA:BB:CC
  connect 98:59:49:AA:BB:CC
```

## Gotchas

- **In the case, the glasses only stay connected long enough to bond.** They drop
  the link because they are docked/charging. Take them out to get a stable
  connection.
- **NoInputNoOutput agent** avoids a passkey prompt on the PC. The glasses accept
  the bond because putting them in pairing mode is the authorization.
- **Multipoint:** re-pairing the PC may drop the glasses from a phone if they do
  not hold two connections at once. Switch back from the phone if needed.
- Profiles: PipeWire/PulseAudio exposes an A2DP sink for music and an HFP
  headset profile for calls. Switch with `pactl` or your audio settings.
