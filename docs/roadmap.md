# Roadmap SALOMON

## Phase 1 — Contrats et compatibilité

- [x] `Salomon.toml` schema version 1
- [x] alias CLI `salomon`
- [x] mode rapide `salomon fuzz --target ... --input ...`
- [x] contrats Rust `salomon-core`
- [x] premier fichier protobuf
- [ ] tests de compatibilité croisée Python/Rust

## Phase 2 — Performance locale

- [ ] Corpus Manager Rust
- [ ] scheduler fast/rare/weighted
- [ ] index de couverture natif
- [ ] forkserver POSIX
- [ ] import/export AFL++ queue

## Phase 3 — Analyse et instrumentation

- [ ] SanitizerCoverage runtime
- [ ] profils ASan/UBSan/MSan/TSan
- [ ] clustering de stack traces
- [ ] grammar mutators JSON/XML/protocoles
- [ ] minimisation guidée par couverture

## Phase 4 — Distribution

- [ ] master/worker gRPC authentifié
- [ ] synchronisation de corpus par hashes
- [ ] quotas et heartbeats workers
- [ ] reprise après perte d'un worker

## Phase 5 — Version 1.0

- [ ] installateur `cargo install`
- [ ] Docker et image LLVM
- [ ] wrappers `salomon-clang` / `salomon-clang++`
- [ ] dashboard couverture temps réel
- [ ] documentation et exemples multi-plateformes
