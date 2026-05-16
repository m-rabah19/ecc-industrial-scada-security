# Industrial SCADA Security — Known Limitations

Listed honestly so reviewers and interviewers can see exactly what this
simulation does **not** do and why. Knowing the boundaries of your own
work is engineering maturity.

---

## Cryptographic limitations

### Toy curve parameters
The simulation runs point arithmetic on a textbook elliptic curve with
`p = 23`, `a = 1`, `b = 1`, base point `G = (0, 1)`. This is *not* secure
cryptography — it is a curve small enough to make every step
inspectable by hand. Real industrial deployments would use **secp256k1**
(Bitcoin/Ethereum standard) or **NIST P-256**, both with 256-bit primes.
The mathematics is identical; only the parameters change.

The `useRealCurveSpec` flag in `eccParams()` switches the *parameter
display* to secp256k1, but the actual point arithmetic still runs on the
small curve because MATLAB lacks native big-integer support. A real
implementation would call into a cryptographic library
(OpenSSL/libsodium/BoringSSL) rather than doing modular arithmetic in
interpreted MATLAB.

### Simplified signature scheme
`generateECCSignature` is a hash-and-sign placeholder that returns
`(sum(msg) + secret) mod 997`. Real ECDSA computes:

```
  r = (k * G).x mod n
  s = k^{-1} * (z + r * d) mod n
```

where `k` is a *cryptographically random* nonce, unique per signature,
and `z` is a proper hash of the message (SHA-256 or similar). RFC 6979
specifies deterministic-k derivation to avoid the failure mode that
broke the Sony PlayStation 3's signing key in 2010.

The demonstration captures the *principle* — modifying the message
breaks the signature — but is not a secure ECDSA implementation.

### No replay protection in the cryptographic layer
The replay-window check is enforced by the receiver application, not by
the signature itself. A real protocol would bind the timestamp into the
signed payload using a structured format (e.g., CBOR + COSE) so the
timestamp cannot be modified without invalidating the signature.

### ECDH shared secret is not run through a KDF
The simulation uses the raw x-coordinate of the shared point as the
"shared secret." Real implementations run the x-coordinate through a
**key derivation function** (HKDF/X9.63 KDF) to produce uniformly random
keying material suitable for symmetric encryption.

---

## Detection-engine limitations

### Confidence weights are heuristic
The 70/15/10/5 confidence weights for signature/replay/sequence/rate
violations are chosen for plausibility, not derived from data. A real
SIEM or anomaly-detection system would tune these against historical
ground-truth events, possibly with a learned model on top.

### Command-sequence state machine is intentionally small
Only five illegal transitions are encoded
(`STOP_MOTOR -> STOP_MOTOR`, `EMERGENCY_HALT -> SET_SPEED`, etc.). A
production system would encode the full state graph of the underlying
process — typically dozens of valid transitions per device class — and
flag anything off the graph.

### Replay-window assumes synchronised clocks
The detector compares the message timestamp to a local arrival clock
within a 5-second window. Industrial plants typically use IEEE 1588
(PTP) or NTP for time synchronisation; without it, this check produces
false positives on clock drift. Production deployments would tolerate
larger windows or use authenticated time sources.

### No anomaly detection on the *content* of legitimate commands
A signed and timely command that sets a pump to 200 % capacity will
pass every check in this simulation. Real OT security adds a
**process-aware** layer (sometimes called "deep packet inspection for
ICS protocols") that knows valid setpoint ranges for each device. That
is out of scope here.

---

## Engineering limitations

### Single-shot batch simulation
The script processes `n_attacks` messages in a tight loop and reports
aggregate statistics. There is no streaming/online mode, no integration
with a real SCADA protocol stack (Modbus/TCP, IEC 60870-5-104,
DNP3), and no logging of individual events to disk for forensic review.

### Hardcoded attacker model
The attacker tampers ~80 % of intercepted messages and uses a fixed
substitution table (`SET_SPEED -> STOP_MOTOR`, etc.). A real adversary
would adapt — using replay attacks, command-injection across legitimate
sessions, and combinations of small modifications. The current model is
adequate for demonstrating the detection layers; it is not adequate for
evaluating real-world security posture.

### Force-directed layout is naive
The `forceDirectedLayout` function uses a simple Fruchterman-Reingold
implementation with quadratic complexity in node count. It works for
plants up to ~20 machines; beyond that, layout times become noticeable
and overlap-avoidance becomes unreliable. A real visualisation would
use specialised graph-drawing libraries (Graphviz, Cytoscape).

### No persistence between runs
Each run starts with empty state for the replay-window cache, command
sequence tracker, and rate-limit window. In production, this state
would be persisted to allow detection across restarts.

---

## What would make this a real product

In rough order of effort:

1. **Replace toy curve with real ECDSA library calls** — link to MbedTLS
   or BoringSSL for actual 256-bit operations.
2. **Implement RFC 6979 deterministic-k** for signature generation.
3. **Integrate with a real SCADA protocol stack** — wrap signed messages
   in Modbus/TCP frames, deploy to a hardware PLC + HMI testbed.
4. **Bind the timestamp into the signed payload** using a structured
   format (CBOR + COSE).
5. **Add HKDF** on top of the ECDH shared secret.
6. **Persist detection state** to disk or a SIEM (Splunk, ELK).
7. **Add process-aware deep packet inspection** with per-device setpoint
   range validation.
8. **Tune confidence weights** against ground-truth security events.
9. **Add unit tests** covering each detection layer in isolation.
10. **Performance characterisation** — measure latency overhead added by
    signature verification on real PLC hardware.

None of the above are missing because they are unknown; they are
missing because they have prerequisites — real hardware, real SCADA
traffic, a real curve library — that this academic simulation does not
have.

---

## Author

**Muhammed Rabah Mundathote**
