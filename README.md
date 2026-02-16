# ECC-Based Industrial SCADA Security Simulation

This project implements a cybersecurity framework for protecting HMI–PLC communication in industrial control systems using Elliptic Curve Cryptography (ECC).

The simulation models a cyber–physical industrial plant under Man-in-the-Middle (MITM) attacks and demonstrates how ECC-based authentication and anomaly detection can intercept malicious commands in real time.

---

## Project Overview

Industrial automation systems rely on secure communication between Human–Machine Interfaces (HMIs) and Programmable Logic Controllers (PLCs). Legacy SCADA protocols often transmit commands in plaintext, making them vulnerable to interception, replay, and tampering.

This project proposes a lightweight ECC security architecture that:

- establishes secure key exchange
- digitally signs control commands
- detects MITM attacks
- blocks tampered messages before execution
- measures detection latency and interception rate

The framework is evaluated using a configurable industrial plant simulator.

---

## Features

- ECC key generation and shared secret establishment
- Digital signature simulation
- Multi-layer intrusion detection engine
- MITM attack simulation
- Replay and command tampering detection
- Real-time performance metrics
- Interactive plant configuration
- Visual security dashboard

---

## Simulation Outputs

The system generates:

- plant topology visualization
- attack interception timeline
- cumulative prevention graph
- detection latency histogram
- security performance dashboard

Example metrics from simulation:

Total attacks: 25
Intercepted: 22
Prevention rate: 88%
Average detection latency: 262 ms

---

## Requirements

- MATLAB (R2021 or later recommended)
- No external toolboxes required

---

## How to Run

1. Open MATLAB
2. Navigate to the project folder
3. Run:
```matlab
industrial_scada_ecc_security
```
4. Enter plant parameters when prompted
5. Observe simulation dashboard

## File Structure

```
industrial_scada_security.m   → main simulation code
```

---

## Purpose

This project demonstrates how cryptographic protection can be embedded directly into industrial control loops to improve cybersecurity without violating real-time constraints.

It serves as a research prototype for:

- smart factory security
- SCADA protection
- IIoT communication security
- cyber–physical system resilience

---

## Future Extensions

- hardware-in-the-loop PLC testing
- production-grade ECC curves
- machine learning intrusion detection
- automated key management
- integration with industrial protocols

---

## License

This project is for academic and research use.

---

## Author

Muhammed Rabah  
