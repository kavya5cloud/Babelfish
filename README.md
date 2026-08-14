<img width="824" height="272" alt="Screenshot 2026-08-13 at 10 26 55 PM" src="https://github.com/user-attachments/assets/09a6aecb-a3e6-48d5-81d1-704d46dbd856" />

# BABELFISH

```text
        Automated Reverse Engineering
        for Undocumented Binary Protocols
```

> Turn raw bytes into a protocol hypothesis.

---

## WHAT IS BABELFISH?

Machines talk.

A solar inverter talks to its controller.
A PLC talks to an HMI.
A car talks over CAN.
An EV charger talks to its backend.
A sensor talks to a gateway.

The problem?

A lot of these devices speak **private, undocumented binary protocols**.

Instead of:

```text
temperature = 31.4°C
```

you get:

```text
7E 04 01 2C 00 5A 3F
7E 04 01 2E 00 5A 41
7E 04 01 2F 00 59 42
```

Babelfish tries to answer:

```text
        WHAT DOES THIS BYTE STREAM MEAN?
                     |
                     v
        +-----------------------------+
        |     Protocol Inference      |
        +-----------------------------+
                     |
          +----------+----------+
          |          |          |
          v          v          v
       Framing    Checksum    Fields
          |          |          |
          +----------+----------+
                     |
                     v
              Protocol Model
```

---

## THE CORE IDEA

Babelfish does **not** start by asking an LLM to guess what bytes mean.

It starts with evidence.

The current approach is:

```text
RAW BYTES
   |
   v
FRAME HYPOTHESIS
   |
   v
CHECKSUM HYPOTHESIS
   |
   v
VALIDATE ACROSS MANY FRAMES
   |
   v
STRUCTURE
   |
   v
SEMANTICS
```

Checksums are especially useful because a checksum candidate can be tested against repeated frames.

A candidate that validates:

```text
1000 / 1000
```

is much stronger evidence than:

```text
12 / 1000
```

Babelfish uses that validation as an anchor for later protocol inference.

---

## CURRENT PIPELINE

```text
                    BABELFISH
                        |
                        v
                +---------------+
                |  Raw Capture  |
                +---------------+
                        |
                        v
                +---------------+
                | Frame Search  |
                +---------------+
                        |
                        v
                +---------------+
                |   Framing     |
                +---------------+
                        |
                        v
                +---------------+
                |   Checksum    |
                |    Search     |
                +---------------+
                        |
                        v
                +---------------+
                |   Coverage    |
                |    Search     |
                +---------------+
                        |
                        v
                +---------------+
                |  Validation   |
                +---------------+
                        |
                        v
                +---------------+
                |  Confidence   |
                +---------------+
                        |
                        v
                +---------------+
                |    Verdict    |
                +---------------+
                        |
                        v
                +---------------+
                | Best Hypothesis|
                +---------------+
```

---

# CURRENTLY IMPLEMENTED

### Checksum algorithms

```text
[✓] CRC16/MODBUS
[✓] CRC8
[✓] XOR
[✓] SUM8
[✓] SUM16
```

### Analysis

```text
[✓] Checksum validation
[✓] Variable-length frames
[✓] Checksum position inference
[✓] Checksum coverage inference
[✓] Candidate ranking
[✓] Validation rate
[✓] Confidence score
[✓] Candidate verdicts
[✓] Failed-frame indexes
```

### Framing

```text
[✓] Recurring-prefix detection
[✓] Prefix-based frame splitting
[✓] Framing candidate generation
[✓] Raw stream → frames → checksum inference
```

### Input / CLI

```text
[✓] Hex capture parser
[✓] One-frame-per-line capture format
[✓] `babelfish crack <capture>`
[✓] Human-readable candidate report
```

---

# EXAMPLE

Input:

```text
7E 10 00 01 02 33
7E 10 01 01 02 2A
7E 10 02 01 02 21
...
```

Babelfish can produce a hypothesis such as:

```text
Babelfish

Frames: 100

Candidates:

  CRC8
  100/100
  100.00%
  PROVEN

  coverage: bytes[1..5]
  checksum: bytes[5..6]
  failed: 0
```

Meaning:

```text
7E | 10 00 01 02 | 33
 ^       DATA       ^
 |                  |
HEADER            CRC8
```

The important point is that Babelfish can discover that the header byte is **not included** in the checksum.

---

# CLI

Basic usage:

```bash
cargo run -- crack capture.txt
```

Example:

```text
Babelfish 🐟

Frames: 100

Candidates:

  CRC16/MODBUS    100/100   100.00%    PROVEN
  CRC8              2/100     2.00%  REJECTED
  XOR               2/100     2.00%  REJECTED
  SUM8              1/100     1.00%  REJECTED
  SUM16             0/100     0.00%  REJECTED

Best candidate:

  CRC16/MODBUS
```

For weaker candidates, Babelfish can report failed frame indexes:

```text
CRC8
failed indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, ...]
```

---

# INPUT FORMAT

Current capture format:

```text
01 02 03 04 A1 2B
10 20 30 40 8B D4
AA BB CC DD 00 00
```

One frame per line.

Blank lines are ignored.

Comments beginning with `#` are ignored.

Example:

```text
# request
7E 01 10 02 33

# response
7E 02 10 01 45
```

---

# WHY CHECKSUMS FIRST?

Protocol structure often leaves mathematical fingerprints.

Checksums are especially useful because they provide a strong validation signal.

Instead of saying:

```text
"I think byte 4 might be a checksum."
```

Babelfish can ask:

```text
Does this algorithm validate every frame?
```

For example:

```text
CRC16/MODBUS

100 / 100
^^^^^^^^^

PROVEN
```

That hypothesis can then support later structural inference.

---

# DESIGN PRINCIPLE

```text
       EVIDENCE
          |
          v
      STRUCTURE
          |
          v
       SEMANTICS
```

Babelfish should prefer:

```text
UNKNOWN
INSUFFICIENT EVIDENCE
NEAR-MISS
```

over inventing an answer.

A reverse-engineering tool should be able to say:

```text
"I don't know."
```

---

# ROADMAP

```text
PHASE 1
-------
[✓] Checksum algorithms
[✓] Checksum validation
[✓] Coverage inference
[✓] Candidate ranking
[✓] Confidence
[✓] CLI
[✓] Basic framing

PHASE 2
-------
[ ] Better frame delimitation
[ ] Timing-gap detection
[ ] Length-field hypotheses
[ ] Framing + checksum joint scoring
[ ] Robust boundary inference
[ ] CRC catalogue expansion

PHASE 3
-------
[ ] Field alignment
[ ] Constant detection
[ ] Counter detection
[ ] Enum detection
[ ] Integer inference
[ ] Timestamp inference
[ ] Bit-field analysis

PHASE 4
-------
[ ] Request/response pairing
[ ] State-machine inference
[ ] Protocol visualization

PHASE 5
-------
[ ] Kaitai Struct generation
[ ] Python parser generation
[ ] Rust parser generation
[ ] Wireshark dissector generation

PHASE 6
-------
[ ] Protocol fingerprints
[ ] Corpus search
[ ] Similarity matching
[ ] Protocol-family clustering

PHASE 7
-------
[ ] Active differential probing
[ ] Live capture agent
[ ] Hardware-assisted inference

FUTURE
------
[ ] Semantic inference
[ ] Learned protocol fingerprints
[ ] Confidence calibration
[ ] Byte-stream models
```

---

# ENGINEERING PHILOSOPHY

```text
1. Evidence > Guessing

2. Classical algorithms first

3. AI only where it adds value

4. Every inference should be explainable

5. Deterministic results where possible

6. Test every hypothesis

7. Don't build infrastructure before proving the engine
```

---

# PROJECT STATUS

```text
STATUS:       Early Research / Engineering Prototype

LANGUAGE:     Rust

DOMAIN:       Binary Protocol Reverse Engineering

PRIMARY USE:  Protocol Analysis / Embedded Systems /
              Security Research / Industrial Systems

LICENSE:      TBD
```

---

# WHY "BABELFISH"?

A Babel fish translates an unknown language.

Babelfish does the same thing for machines:

```text
HUMAN LANGUAGE
      |
      v
"What's the temperature?"

      X

MACHINE LANGUAGE
      |
      v
7E 04 01 2C 00 5A 3F
```

Babelfish sits in the middle.

```text
       MACHINE
          |
          | undocumented bytes
          v
    +-------------+
    |  BABELFISH  |
    +-------------+
          |
          | protocol hypothesis
          v
      ENGINEER
```

---

# CONTRIBUTING

Babelfish is currently being developed as an experimental protocol reverse-engineering engine.

Contributions, protocol captures, algorithm implementations, benchmarks, and research ideas are welcome as the project architecture stabilizes.

---

```text
  "Every machine has a language.
   Babelfish is learning how to listen."

                         🐟
```

