# ADR 0001: Rust for the Reference Runtime

## Status

Accepted

## Context

HSP exposes parser-heavy, network-facing, streaming-first surfaces over QUIC and
HTTP/3. The `public multi-tenant` deployment profile raises the cost of memory
safety defects.

## Decision

Use Rust as the primary implementation language for:

- native server
- gateway
- protocol parsers
- storage and auth engines
- conformance harness

Go remains required for the SDK and CLI.

## Consequences

- memory safety becomes the default baseline for the most exposed runtime code
- Rust crates define the canonical typed model used by the reference runtime
- C++ is not used as the primary runtime language

