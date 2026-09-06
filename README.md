<img width="824" height="272" alt="Screenshot 2026-08-13 at 10 26 55 PM" src="https://github.com/user-attachments/assets/09a6aecb-a3e6-48d5-81d1-704d46dbd856" />

# BABELFISH 🐟

> **Automated reverse engineering for undocumented binary protocols.**

Turn raw hexadecimal captures into an **evidence-backed protocol hypothesis**, explain what Babelfish discovered, and generate a Rust parser from the inferred model.

```text
        UNDOCUMENTED BINARY CAPTURE
                    │
                    ▼
             ┌─────────────┐
             │   FRAMING   │
             └──────┬──────┘
                    ▼
             ┌─────────────┐
             │  CHECKSUM   │
             └──────┬──────┘
                    ▼
             ┌─────────────┐
             │    FIELDS   │
             └──────┬──────┘
                    ▼
             ┌─────────────┐
             │   PROTOCOL  │
             │    MODEL    │
             └──────┬──────┘
                    │
              ┌─────┴─────┐
              ▼           ▼
          EXPLAIN       GENERATE
              │           │
              ▼           ▼
         HUMAN VIEW    RUST PARSER
````

---

## What is Babelfish?

Machines communicate through protocols.

A solar inverter talks to its controller.
A PLC talks to an HMI.
A sensor talks to a gateway.
A vehicle communicates over CAN.
An industrial device exchanges binary frames with software.

The problem is that many of these protocols are **private, undocumented, proprietary, or poorly documented**.

Instead of:

```text
temperature = 31.4°C
```

an engineer may see:

```text
7E 04 01 2C 00 5A 3F
7E 04 01 2E 00 5A 41
7E 04 01 2F 00 59 42
```

Babelfish attempts to work backwards from those bytes.

Its goal is not to randomly guess what a byte means.

Its goal is to find **repeatable evidence** for:

* frame boundaries
* checksums
* checksum coverage
* field structure
* counters
* numeric representations
* multi-byte interpretations
* protocol-level hypotheses

The result is a structured `ProtocolModel` that can be inspected or used to generate code.

---

# Core Idea

Babelfish follows an evidence-first pipeline:

```text
RAW CAPTURE
     │
     ▼
FRAME HYPOTHESIS
     │
     ▼
CHECKSUM SEARCH
     │
     ▼
CHECKSUM VALIDATION
     │
     ▼
FIELD ANALYSIS
     │
     ▼
PROTOCOL HYPOTHESIS
     │
     ▼
PROTOCOL MODEL
     │
     ├───────────────┐
     ▼               ▼
  EXPLAIN         GENERATE
                      │
                      ▼
                 RUST PARSER
```

The important principle is:

> **Evidence before semantics.**

A protocol reverse-engineering system should prefer a qualified hypothesis over an invented answer.

---

# Current Capabilities

## Framing

Babelfish currently supports evidence-based framing analysis including:

```text
[✓] Recurring-prefix detection
[✓] Prefix-based framing
[✓] Length-field framing
[✓] Frame candidate generation
[✓] Raw stream → frames
```

Framing candidates can subsequently participate in protocol inference.

---

## Checksum Inference

Babelfish searches for checksum algorithms and validates candidates across captured frames.

Currently implemented checksum families include:

```text
[✓] CRC16/MODBUS
[✓] CRC8
[✓] XOR
[✓] SUM8
[✓] SUM16
```

For each candidate, Babelfish can reason about:

```text
algorithm
validation count
validation rate
checksum position
coverage range
failed frames
candidate verdict
```

For example:

```text
CRC16/MODBUS

100 / 100
100.00%
PROVEN

coverage: bytes[0..4]
checksum: bytes[4..6]
```

A candidate that validates every frame is substantially stronger evidence than one that only happens to match a few frames.

---

# Field Inference

Once structural evidence has been established, Babelfish analyzes byte positions for recurring patterns.

Current model-level inference includes:

```text
[✓] Per-byte field hypotheses
[✓] Constant / variable behavior
[✓] Counter-like sequences
[✓] Linear step detection
[✓] Numeric range analysis
[✓] Multi-byte field hypotheses
[✓] Endianness interpretations
[✓] Confidence values
```

For example:

```text
byte[3..4]  counter_3
interpretation: counter(step=1)
confidence: 100%
```

Field interpretations remain **hypotheses**, not automatically confirmed semantic labels.

---

# Protocol Model

Babelfish combines the individual inference stages into a structured protocol representation.

Conceptually:

```text
ProtocolModel
│
├── Framing
│   ├── kind
│   ├── frame count
│   ├── length information
│   └── checksum width
│
├── Checksum
│   ├── algorithm
│   ├── coverage
│   └── checksum position
│
├── Fields
│   ├── byte ranges
│   ├── types
│   ├── interpretations
│   └── confidence
│
├── Multi-byte fields
│   └── numeric interpretations
│
└── Evidence
    ├── observations
    ├── scores
    └── supporting statements
```

This model is the bridge between raw captures and generated parsers.

---

# Human-Readable Explanation

Babelfish can explain what it inferred:

```bash
cargo run -- explain crc16_capture.txt
```

Example:

```text
Babelfish 🐟

Protocol Explanation
====================

Frames
------
  detected: 100

Framing
-------
  prefix []
  checksum width: 2 byte(s)

Checksum
--------
  algorithm: CRC16/MODBUS
  coverage: bytes[0..4]
  checksum: bytes[4..6]

Fields
------
  byte[0..2]  value_0          u16    U16BigEndian  confidence: 100%
  byte[2..3]  field_2          u8     variable  confidence: 25%
  byte[3..4]  counter_3        u8     counter(step=1)  confidence: 100%

Evidence
--------
  evidence items: 7
  strongest evidence: 1.00
  bytes[0..2] → U16BigEndian
```

The purpose of `explain` is to make the reasoning visible instead of returning only a final answer.

---

# Rust Parser Generation

Babelfish can generate a Rust parser from an inferred protocol model.

```bash
cargo run -- generate crc16_capture.txt --lang rust
```

The generated parser includes validation logic and tests against the captured frames.

The generation pipeline is:

```text
capture
   │
   ▼
ProtocolModel
   │
   ▼
Rust generator
   │
   ▼
parser.rs
   │
   ├── frame parsing
   ├── checksum validation
   └── generated tests
```

The generated parser is intended to make the inferred protocol executable and independently testable.

---

# CLI

## `crack`

Analyze an already-framed capture and rank checksum candidates.

```bash
cargo run -- crack capture.txt
```

---

## `crack-stream`

Analyze a raw hexadecimal stream and attempt to discover frame boundaries before checksum analysis.

```bash
cargo run -- crack-stream stream.txt
```

JSON output is also available:

```bash
cargo run -- crack-stream stream.txt --json
```

---

## `explain`

Build a protocol model and present the current inference in human-readable form.

```bash
cargo run -- explain capture.txt
```

This is the easiest command for understanding what Babelfish currently believes about a capture.

---

## `generate`

Generate a Rust parser from an already-framed capture.

```bash
cargo run -- generate capture.txt --lang rust
```

Currently supported:

```text
rust
```

---

# Input Format

The current capture format is:

> **One complete frame per line, represented as hexadecimal bytes.**

Example:

```text
01 00 00 0A 81 DF
01 01 03 0B 11 2F
01 02 06 0C 41 7E
```

Whitespace-separated hexadecimal bytes are accepted.

Comments beginning with `#` can be used in capture files:

```text
# request
7E 01 10 02 33

# response
7E 02 10 01 45
```

Blank lines are ignored.

For `crack-stream`, the input represents a continuous hexadecimal stream rather than pre-delimited frames.

---

# Example: CRC16 Capture

Suppose a capture contains frames such as:

```text
01 00 00 0A 81 DF
01 01 03 0B 11 2F
01 02 06 0C 41 7E
...
```

Running:

```bash
cargo run -- explain crc16_capture.txt
```

can produce:

```text
Frames
------
  detected: 100

Checksum
--------
  algorithm: CRC16/MODBUS
  coverage: bytes[0..4]
  checksum: bytes[4..6]
```

The important discovery is not simply:

```text
CRC16/MODBUS
```

but the complete structural hypothesis:

```text
┌────────────── DATA ──────────────┐
01 00 00 0A       81 DF
└───────────────┬──────────────────┘
                │
             CRC16
```

with the checksum validated against the captured frames.

---

# Evidence and Confidence

Babelfish distinguishes between **observations** and **interpretations**.

For example:

```text
Observed:
bytes 3..4 change with a consistent step.

Inference:
this is consistent with a counter.

Confidence:
100%
```

A confidence score is therefore not the same thing as a semantic guarantee.

The intended progression is:

```text
OBSERVATION
     │
     ▼
PATTERN
     │
     ▼
HYPOTHESIS
     │
     ▼
CONFIDENCE
     │
     ▼
MODEL
```

This matters because binary protocols frequently contain fields whose true meaning cannot be established from passive captures alone.

Babelfish should therefore be comfortable saying:

```text
UNKNOWN
```

or:

```text
INSUFFICIENT EVIDENCE
```

rather than inventing semantics.

---

# Why Checksums Matter

Checksums provide one of the strongest mathematical signals available during passive protocol analysis.

Consider:

```text
Candidate A

1000 / 1000 frames
```

versus:

```text
Candidate B

12 / 1000 frames
```

Candidate A has much stronger evidence.

This allows Babelfish to use checksum validation as an anchor for subsequent structural inference:

```text
CHECKSUM
   │
   ▼
TRUSTED STRUCTURE
   │
   ▼
FIELD ANALYSIS
   │
   ▼
PROTOCOL HYPOTHESIS
```

This is one reason the project emphasizes deterministic analysis before learned semantic interpretation.

---

# Testing

Babelfish currently has a regression suite covering framing, checksum analysis, field inference, protocol modeling, and related behavior.

Current baseline:

```text
cargo test

61 passed
0 failed
0 ignored
```

Generated Rust parsers are also validated against captured frames and deliberately corrupted frames.

The intended validation loop is:

```text
CAPTURE
   │
   ▼
INFER
   │
   ▼
GENERATE
   │
   ▼
COMPILE
   │
   ▼
TEST AGAINST CAPTURE
```

This keeps the inference engine grounded in executable behavior rather than only textual output.

---

# Architecture

At a high level:

```text
                    ┌─────────────────────┐
                    │     HEX CAPTURE     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │       INPUT         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      FRAMING        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      CHECKSUM       │
                    │       SEARCH        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   FIELD INFERENCE   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   PROTOCOL MODEL    │
                    └──────────┬──────────┘
                               │
                     ┌─────────┴─────────┐
                     ▼                   ▼
              ┌─────────────┐     ┌─────────────┐
              │   EXPLAIN   │     │   GENERATE  │
              └─────────────┘     └──────┬──────┘
                                         │
                                         ▼
                                  ┌─────────────┐
                                  │ RUST PARSER │
                                  └─────────────┘
```

The implementation is written in Rust.

---

# Roadmap

## Phase 1 — Protocol Inference Foundation

```text
[✓] Checksum algorithms
[✓] Checksum validation
[✓] Checksum position inference
[✓] Checksum coverage inference
[✓] Candidate ranking
[✓] Validation rate
[✓] Candidate verdicts
[✓] Basic framing
[✓] Field hypotheses
[✓] Multi-byte hypotheses
[✓] Protocol model
[✓] Human-readable explanation
[✓] Rust parser generation
```

## Phase 2 — Stronger Structural Inference

```text
[ ] Better frame delimitation
[ ] Timing-gap detection
[ ] Stronger length-field inference
[ ] Joint framing + checksum scoring
[ ] Robust boundary inference
[ ] Larger CRC catalogue
[ ] Better confidence calibration
```

## Phase 3 — Richer Field Semantics

```text
[ ] Constant detection improvements
[ ] Counter detection improvements
[ ] Enum detection
[ ] Signed integer inference
[ ] Floating-point inference
[ ] Timestamp inference
[ ] Bit-field analysis
[ ] Scaling / offset hypotheses
```

## Phase 4 — Protocol Behavior

```text
[ ] Request / response pairing
[ ] Message classification
[ ] State-machine inference
[ ] Protocol visualization
```

## Phase 5 — Code Generation

```text
[ ] Python parser generation
[ ] Go parser generation
[ ] Kaitai Struct generation
[ ] Wireshark dissector generation
```

## Phase 6 — Protocol Intelligence

```text
[ ] Protocol fingerprints
[ ] Corpus search
[ ] Similarity matching
[ ] Protocol-family clustering
```

## Phase 7 — Active Reverse Engineering

```text
[ ] Differential probing
[ ] Live capture agent
[ ] Hardware-assisted inference
[ ] Active protocol experimentation
```

## Long-Term Research

```text
[ ] Semantic inference
[ ] Learned protocol representations
[ ] Learned byte-stream models
[ ] Cross-protocol structural embeddings
[ ] Confidence calibration at scale
```

---

# Engineering Philosophy

### 1. Evidence > Guessing

Every inference should be supported by measurable observations where possible.

### 2. Classical algorithms first

Deterministic statistical and mathematical techniques are useful for many low-level protocol properties.

### 3. AI only where it adds value

Machine learning should help where deterministic analysis reaches its limits — not replace simple evidence with opaque guesses.

### 4. Explainability matters

A protocol hypothesis should come with evidence explaining why it was proposed.

### 5. Validate hypotheses

A parser generated from an inferred protocol should be tested against real captured frames.

### 6. Preserve uncertainty

Not every unknown byte has an identifiable meaning from passive traffic alone.

### 7. Prove the engine before building infrastructure

The inference engine is the core asset. Web applications, distributed workers, databases, and live hardware integrations come later.

---

# Project Status

```text
STATUS:       Research / Engineering Prototype

LANGUAGE:     Rust

DOMAIN:       Binary Protocol Reverse Engineering

CURRENT FOCUS:
              Deterministic protocol inference,
              evidence-backed hypotheses,
              explainability,
              and executable parser generation.
```

Babelfish is currently a **local CLI research and engineering tool**, not yet a production protocol-analysis platform.

---

# Contributing

Babelfish is being developed as an experimental protocol reverse-engineering engine.

Useful contributions include:

* checksum algorithms
* framing strategies
* inference techniques
* protocol captures
* regression fixtures
* benchmarks
* parser generators
* protocol-analysis research

When adding an inference technique, prefer adding:

```text
implementation
+
evidence
+
tests
+
explanation
```

rather than only adding a final guess.

---

# License

License: **TBD**

---

# Why "Babelfish"?

A Babel fish translates between languages.

Babelfish applies the metaphor to machines:

```text
             MACHINE
                │
                │ undocumented bytes
                ▼
        ┌─────────────────┐
        │    BABELFISH    │
        └────────┬────────┘
                 │
                 │ protocol hypothesis
                 ▼
              ENGINEER
```

The goal is simple:

> **Every machine has a language. Babelfish is learning how to listen.**

🐟

```
```
