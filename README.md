# ECC-Based MITM Protection for Industrial SCADA

A MATLAB simulation demonstrating elliptic curve cryptography (ECC) protection
of HMI–PLC communications in industrial SCADA systems, with man-in-the-middle
attack injection and a four-layer receiver-side intrusion detection engine.

The simulation positions itself explicitly within an ISA/IEC 62443
defense-in-depth architecture and is honest about its scope: it protects
one conduit between Purdue Level 2 (HMI) and Level 1 (PLC). See
[`SECURITY_ARCHITECTURE.md`](SECURITY_ARCHITECTURE.md) for the full
architectural context.

---

## What it does

**Cryptographic core**
- ECDH key exchange between HMI and PLC produces a shared secret
- Every command from HMI to PLC is signed (simplified ECDSA-style scheme)
- The PLC verifies the signature on receipt; any modification breaks it

**Four-layer receiver-side detection**

| Layer | Confidence weight | What it catches |
|---|---|---|
| ECC signature verification | 70% | Message tampering (the primary defense) |
| Replay-window check | 15% | Duplicate timestamps, out-of-window arrivals |
| Command-sequence state machine | 10% | Illegal command transitions |
| Rate-limit detector | 5% | Burst command injection |

A confidence score ≥ 50% triggers an alert. Signature failure alone
crosses the threshold.

**Realistic MITM attacker**
- Intercepts every message
- Tampers ~80% of intercepted traffic (industrial command substitution:
  `SET_SPEED → STOP_MOTOR`, `OPEN_VALVE → CLOSE_VALVE`, etc.)
- Passes ~20% unchanged (passive reconnaissance)

---

## Running the simulation

### Requirements

- MATLAB R2020b or later (no toolboxes required)

### Three modes

```matlab
industrial_scada_security('--demo')   % 3-machine preset, no typing
industrial_scada_security('--big')    % 6-machine preset, force-directed layout
industrial_scada_security()           % interactive plant configuration
```

The `--demo` mode is the fastest way to see the simulation end-to-end:
it skips the input prompts and uses a sensible 3-machine plant preset.

### Typical output

```
=== INDUSTRIAL PLANT SCADA SECURITY (ECC-based MITM Protection) ===
Curve in use: demo y^2 = x^3 + 1x + 1 mod 23, G=(0,1)
Secure ECC channel established (shared secret = 7)
Simulating MITM attacks...

=== SUMMARY ===
Total intercepted attempts: 25
  Tampered (real attacks):  21
    Intercepted by ECC:     21
    Slipped through:        0
  Clean (passive recon):    4

Detection rate (tampered only): 100.00%
Overall prevention rate:        84.00%
Avg detection latency (sim):    275.0 ms
```

A six-panel MATLAB figure renders alongside the console output:

1. **Plant topology** — auto-layout, color-coded by per-machine attack outcome
2. **Process values** — bar chart of measured values per machine
3. **Attack interception timeline** — per-attack outcome over time
4. **Cumulative prevention performance** — running tally with success rate
5. **Detection time distribution** — histogram of latency in ms
6. **Detection layer trigger frequency** — which layers actually fired

---

## How it works — high level

```
HMI                                                 PLC
 │                                                   │
 │ 1. ECDH key exchange                              │
 │ ───── public point aG ─────────────────────────► │
 │ ◄──── public point bG ──────────────────────────  │
 │                                                   │
 │ both compute shared secret abG                    │
 │                                                   │
 │ 2. Signed command                                 │
 │ ───── msg + ECC signature ─────► [MITM] ──────►  │
 │                                       │           │
 │                                       │           │
 │                                       ▼           │
 │                              (tamper or pass-through)
 │                                       │           │
 │                                       └─────────► │
 │                                                   │
 │                                          3. Verify signature
 │                                          + replay window
 │                                          + command sequence
 │                                          + rate limit
 │                                                   │
 │                                          Confidence ≥ 50% → alert
```

The MITM cannot forge a valid signature because the signing secret is
derived from the ECDH-shared point — which the attacker cannot compute
without solving the elliptic curve discrete logarithm problem. Any
modification to the message changes the recomputed signature, so the
receiver detects tampering via signature mismatch.

---

## Honest scope and limitations

This is a **simulation** for demonstrating principles, not a deployment-
ready security solution. Specifically:

- The curve used for point arithmetic is a textbook toy (`p = 23`), not
  a real secure curve. Production would use **secp256k1** or **NIST
  P-256** with 256-bit primes.
- The signature scheme is a simplified hash-and-sign for clarity, not
  full ECDSA with proper modular inversion and a random nonce `k`. A
  production implementation must follow RFC 6979 deterministic-k to
  avoid the failure mode that broke the Sony PlayStation 3 signing key
  in 2010.
- The detector confidence weights (70/15/10/5) are heuristic, not
  tuned against ground-truth security events.
- The command-sequence state machine encodes only 5 illegal
  transitions; a real one would encode dozens.

A complete enumeration is in [`LIMITATIONS.md`](LIMITATIONS.md). A
review of where this work fits in a defense-in-depth architecture is
in [`SECURITY_ARCHITECTURE.md`](SECURITY_ARCHITECTURE.md).

---

## Why ECC for SCADA?

In industrial environments where PLCs and field devices have limited
compute and memory, ECC provides equivalent security to RSA at roughly
1/8 the key size and significantly faster signing. For control loops
running at 10–100 ms cadence, this matters.

|              | RSA-2048 | ECC-256 |
|---|---|---|
| Key size     | 256 bytes | 32 bytes |
| Security level | 112 bits | 128 bits |
| Signing speed | slow | fast |
| Suitable for resource-constrained controllers | marginal | yes |

---

## Author

**Muhammed Rabah Mundathote**
Electronics & Instrumentation Engineering, Vellore Institute of Technology
[LinkedIn](https://www.linkedin.com/in/muhammed-rabah-mt/) · muhammedrabah.19@gmail.com

---

## License

This project is shared for academic and portfolio purposes. Please
credit the author if you reuse substantial portions.
