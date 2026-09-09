# SALOMON Rust workspace

Le workspace Rust est optionnel pendant la migration. Le moteur Python reste
la référence d'exécution.

## Crates

- `salomon-core` : contrats partagés entre l'exécuteur, le corpus et le
  feedback ;
- `salomon-corpus` : corpus borné, dédoublonnage exact, scheduler reproductible
  random/feedback et index bitmap de couverture ;
- `salomon-corpusd` : helper IPC local v1, démarré comme enfant et non exposé
  sur le réseau.

## Vérification

Avec Rust installé :

```bash
cargo test --manifest-path rust/Cargo.toml
```

Le pont IPC batché est activé uniquement quand `engine.corpus_backend =
"rust"`. Le crate natif reste testable seul et le backend Python reprend la
main si le helper n'est pas disponible. Une FFI in-process pourra ensuite
réduire le coût de la frontière pour le chemin chaud.
