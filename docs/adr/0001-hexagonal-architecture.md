# ADR 0001: Lightweight hexagonal architecture

Status: Accepted for the proposed refactor

## Context

Discord Gateway delivers asynchronous messages. Spam decisions are local while threat intelligence requires a remote HTTP call. Previously the entry point handled configuration, detection, queues and Discord side effects.

## Decision

Keep a modular monolith with a small application core. The moderation package owns use cases, policies, and consumer-defined inbound/outbound ports. The guard and spam packages remain independent detection modules; the Safe Browsing client and Discord Gateway/REST become adapters. The entry point wires concrete dependencies. Use two bounded in-process workers, one per action path. No broker or database is needed at current scale.

## Consequences

Core tests can use fakes without Discord credentials. Normal creates use the Gateway snapshot, partial edits are fetched, and URL-triggered deletion rechecks the current message. A race between read and delete remains possible. Discord rate limits, queue overflow, and shutdown can still drop work; this is best-effort moderation, not a durable delivery guarantee. Default monitor-only policy and privacy restrictions remain unchanged. Future work: hash-based threat lookup, observability, integration tests, configurable spam rules.
