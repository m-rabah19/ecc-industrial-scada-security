# Security Architecture Context — Where This Project Fits

This document positions `industrial_scada_security.m` within the broader
**defense-in-depth architecture** that secures real industrial control
systems. The simulation implements one specific layer of that
architecture — the cryptographic conduit between an HMI and a PLC —
which is necessary but never sufficient on its own.

The framing here aligns with **ISA/IEC 62443** (the international
standard for industrial automation and control system cybersecurity)
and the **Purdue Reference Model** (the standard reference architecture
for ICS network segmentation).

---

## 1. The honest scope of this simulation

The simulation demonstrates ECC-based protection of a single
communication link:

- ECDH key exchange establishes a shared secret between HMI and PLC
- ECDSA-style signatures bind authentication and integrity to every
  command
- A four-layer receiver-side detector flags signature failures, replay
  attempts, illegal command sequences, and rate-limit violations

**That's it.** The simulation does not address — and a real OT security
architecture must address — at least the following:

- Physical security of the controllers and field devices
- Identity and access management for operators (who can issue commands at all)
- Network segmentation between IT, OT, and safety systems
- Key lifecycle management (generation, distribution, rotation, revocation)
- Detection of compromised but legitimate endpoints
- Safety system separation from control (per IEC 61511 / 62443-3-3)
- Patch management on the controllers themselves
- Monitoring, logging, incident response, forensic capability

Cryptography secures a **communication link**. A SCADA system is much
more than its communication links.

---

## 2. The Purdue Reference Model — where the simulation sits

The Purdue Reference Model is the standard architectural framework for
ICS networks. It divides an industrial environment into hierarchical
levels, each with specific functions and security requirements.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Level 5  │  Enterprise Network          ERP, business systems       │  IT
│  Level 4  │  Site Business Logistics     MES, scheduling             │
├═══════════════════════════════════════════════════════════════════════┤
│  Level 3.5│  Industrial DMZ              Historian replicas, jump   │  ⇄
│           │                              servers, patch management   │
├═══════════════════════════════════════════════════════════════════════┤
│  Level 3  │  Site Operations            Historian, batch mgmt        │  OT
│  Level 2  │  Supervisory Control        HMIs, SCADA workstations     │
│  Level 1  │  Basic Control              PLCs, RTUs, SIS              │
│  Level 0  │  Physical Process           Sensors, actuators, valves   │
└─────────────────────────────────────────────────────────────────────┘
```

(Levels 0–3 form the OT environment; Levels 4–5 are IT; Level 3.5 is the
Industrial DMZ that mediates between them.)

**This simulation models the conduit between Level 2 (HMI) and Level 1
(PLC).** The HMI in our `Real_MITM_Attack` is a Level 2 operator
workstation; the PLC is a Level 1 controller; the MITM attacker sits on
the network path between them. Every other Purdue level — physical
process at Level 0, site operations at Level 3, the DMZ at Level 3.5,
business systems at Levels 4 and 5 — is out of scope for this
simulation but in scope for a real defense-in-depth deployment.

---

## 3. ISA/IEC 62443 — zones, conduits, and security levels

IEC 62443 is the leading international standard for industrial
cybersecurity. It introduces three concepts that frame everything this
simulation does and does not cover.

### 3.1 Zones and conduits

A **zone** is a grouping of assets that share common security
requirements. A **conduit** is the communication path between zones.
IEC 62443-3-2 requires that an asset owner partition the entire IACS
into zones and conduits as part of risk assessment.

For a typical SCADA deployment:

- The HMI/operator workstation lives in a *Supervisory Zone* (Level 2)
- The PLC lives in a *Control Zone* (Level 1)
- The Ethernet link between them is the *conduit* connecting the two zones

**This simulation implements the cryptographic protection of one such
conduit.**

A real IEC 62443 deployment would also define:
- A *Safety Zone* containing the SIS (safety instrumented system),
  which must be separated from the control zone — the Triton/Trisis
  malware in 2017 specifically targeted this boundary in a Saudi
  petrochemical plant
- A *DMZ Zone* (Level 3.5) mediating IT/OT traffic
- *Enterprise Zones* at Levels 4 and 5 for business systems
- Conduits between each pair of zones, each independently risk-assessed

### 3.2 Security Levels (SL 1–4)

IEC 62443-3-3 defines four security levels describing the adversary
each zone or conduit must defend against:

| Level | Adversary profile |
|---|---|
| SL 1 | Casual or coincidental violation |
| SL 2 | Intentional violation, low resources, generic skills, low motivation |
| SL 3 | Intentional violation, moderate resources, IACS-specific skills, moderate motivation |
| SL 4 | Intentional violation, extensive resources, IACS-specific skills, high motivation |

The standard distinguishes **target SL (SL-T)** chosen by risk
assessment, **capability SL (SL-C)** offered by a product, and
**achieved SL (SL-A)** measured in deployment.

**This simulation, with proper 256-bit ECDSA on secp256k1, would
contribute to meeting SL 2 capability requirements for the HMI→PLC
conduit** (intentional violation, low-skill adversary). Reaching SL 3
or SL 4 would require additional layers the simulation does not
implement: certificate-based mutual authentication, hardware security
modules for key storage, anomaly detection at the protocol level, and
formal validation of the cryptographic implementation.

### 3.3 The seven Foundational Requirements (FRs)

IEC 62443-3-3 defines seven foundational requirements that each zone
and conduit must satisfy at its target SL:

| FR | Requirement | Addressed by this simulation? |
|---|---|---|
| FR 1 | Identification and authentication control | ✅ (via ECC signatures) |
| FR 2 | Use control | ❌ (no role-based command authorization) |
| FR 3 | System integrity | ✅ (signature verification catches modification) |
| FR 4 | Data confidentiality | ❌ (messages are signed, not encrypted) |
| FR 5 | Restricted data flow | ❌ (no network segmentation modeled) |
| FR 6 | Timely response to events | ⚠️ (detection occurs but no response automation) |
| FR 7 | Resource availability | ❌ (no protection against DoS or resource exhaustion) |

Three of seven foundational requirements are touched by the simulation;
four are not. **This is the precise scope of what cryptography alone
provides.**

---

## 4. Defense-in-depth — the layers around the conduit

A production-grade architecture wraps the cryptographic conduit in
multiple layers. Each layer assumes the previous one may have failed
and provides additional protection.

```
                   ┌───────────────────────────────────┐
                   │  Physical security (locked cabinets,│
                   │  surveillance, badged access)        │
                   └───────────────┬─────────────────────┘
                                   │
                   ┌───────────────▼─────────────────────┐
                   │  Network segmentation (firewalls,    │
                   │  VLANs, IEC 62443 zone enforcement)  │
                   └───────────────┬─────────────────────┘
                                   │
                   ┌───────────────▼─────────────────────┐
                   │  Identity and access control         │
                   │  (operator authentication, RBAC)     │
                   └───────────────┬─────────────────────┘
                                   │
                   ┌───────────────▼─────────────────────┐
                   │  ★ Cryptographic conduit protection ★│
                   │  (THIS SIMULATION — ECDH + ECDSA)    │
                   └───────────────┬─────────────────────┘
                                   │
                   ┌───────────────▼─────────────────────┐
                   │  Process-aware monitoring (setpoint  │
                   │  range validation, anomaly detection)│
                   └───────────────┬─────────────────────┘
                                   │
                   ┌───────────────▼─────────────────────┐
                   │  Safety system separation (SIS on    │
                   │  isolated network per IEC 61511)     │
                   └───────────────┬─────────────────────┘
                                   │
                   ┌───────────────▼─────────────────────┐
                   │  Continuous monitoring and incident  │
                   │  response (SIEM, OT-aware IDS)       │
                   └─────────────────────────────────────┘
```

**Each layer alone is insufficient. Each is necessary.** The
simulation covers exactly one of these layers, in isolation.

---

## 5. What this simulation cannot detect

To make the limit precise: an attacker who has compromised a
*legitimate* HMI endpoint — for example, by phishing the operator's
credentials or installing malware on the workstation — can send
correctly-signed `OPEN_VALVE` and `SET_SPEED` commands. The PLC will
verify the signature, find it valid, and execute the command.

The cryptographic layer cannot help here. Detection requires:

- **Process-aware anomaly detection** — a command that sets a pump to
  200% capacity is anomalous regardless of who signed it
- **Operator behavior monitoring** — issuing 50 commands in a minute is
  anomalous regardless of authentication
- **Safety instrumented systems** — independently enforced shutdown
  conditions when process variables exceed safe ranges
- **Network-level visibility** — OT-aware intrusion detection systems
  monitoring command patterns

These all live outside the cryptographic conduit. The conduit is
necessary, but the security of the *process* depends on layers above
and below.

---

## 6. Real-world references

Three incidents that illustrate why defense-in-depth, not just
cryptography, is the right framing:

- **Stuxnet (2010)** — modified PLC code on Siemens controllers at a
  uranium enrichment facility. Cryptography on supervisory commands
  would not have stopped this; the malware ran directly on the engineer
  workstation and the PLCs themselves.

- **Triton / Trisis (2017)** — targeted the Schneider Triconex Safety
  Instrumented System at a Saudi petrochemical plant, attempting to
  cause physical damage. The attack succeeded in part because the
  safety zone was not adequately isolated from the control zone, the
  exact failure that IEC 62443 zone segmentation is designed to
  prevent.

- **Colonial Pipeline (2021)** — ransomware on the IT side caused the
  operator to voluntarily shut down OT operations. No OT systems were
  directly compromised; the IT/OT boundary control failed at the
  business decision level rather than the technical one.

In none of these cases would stronger cryptography on the HMI/PLC
conduit have changed the outcome. The lesson is clear: **cryptography
protects the pipe; defense-in-depth protects the process.**

---

## 7. Conclusion

This simulation implements one layer of an IEC 62443-compliant security
architecture: the **cryptographic protection of the conduit between a
Level 2 supervisory system and a Level 1 controller**. It achieves
this with reasonable fidelity given its scope — adaptive intrusion
detection, layered receiver-side validation, and honest reporting of
detection performance.

It is not, and does not claim to be, a complete SCADA security
solution. Real OT environment resilience emerges from applying
cryptography **within a defense-in-depth architecture** that enforces
authenticated command paths, deterministic communication, secure key
lifecycle management, and zone-based isolation per ISA/IEC 62443.

**ECC can protect the pipe. Only a properly engineered defense-in-depth
architecture can protect the process.**

---

## References

- ISA/IEC 62443 series — Industrial communication networks, IT security
  for industrial automation and control systems
- IEC 62443-3-2 — Security risk assessment, system partitioning
- IEC 62443-3-3 — System security requirements and security levels
- IEC 61511 — Functional safety for the process industry sector
- NIST SP 800-82 Rev 3 (2023) — Guide to Operational Technology (OT) Security
- Purdue Enterprise Reference Architecture (PERA), Purdue Laboratory for
  Applied Industrial Control

---

## Author

**Muhammed Rabah Mundathote**
