# SALOMON Rust workspace

Le workspace Rust est optionnel pendant la migration. Le moteur Python reste
la référence d'exécution.

## Crates

- `salomon-core` : contrats partagés entre l'exécuteur, le corpus et le
  feedback ;
- `salomon-corpus` : corpus borné, dédoublonnage exact, scheduler reproductible
  random/feedback et index bitmap de couverture.

## Vérification

Avec Rust installé :

```bash
cargo test --manifest-path rust/Cargo.toml
```

La frontière FFI/IPC n'est pas encore activée. Le crate natif doit d'abord
rester testable seul et servir de référence pour l'extraction progressive du
chemin chaud Python.
