# SALOMON : architecture et migration

## Position actuelle

Le dépôt contient déjà un moteur Python fonctionnel (`fuzz_orchestrator`) pour les
binaires, TCP, UDP et HTTP, ainsi que des adaptateurs AFL++/libFuzzer, le
fuzzing différentiel, la minimisation et un dashboard. Il reste le moteur par
défaut afin de préserver la compatibilité et la rapidité de livraison.

SALOMON est introduit comme une couche de contrats et un nouveau nom de CLI,
pas comme une réécriture brutale.

```text
salomon CLI
    │
    ├── Salomon.toml -> traducteur de compatibilité -> RunConfig
    │
    ├── Python builtin engine (fallback stable)
    │       ├── corpus / scheduler / mutations
    │       ├── binary, TCP, UDP, HTTP, differential targets
    │       └── dashboard / replay / minimize
    │
    └── Rust core (migration progressive)
            ├── salomon-core : contrats
            ├── corpus manager + scheduler
            ├── executor / forkserver
            └── feedback / instrumentation
```

## Contrats de migration

Les concepts partagés sont :

- `Input` / `CorpusEntry` ;
- `ExecutionResult` ;
- `CoverageDelta` ;
- `BugReport` ;
- `CampaignStats`.

Les contrats Rust sont dans `rust/crates/salomon-core`. Le premier Corpus
Manager/Scheduler natif est dans `rust/crates/salomon-corpus`. Un pont IPC local
versionné est fourni par `rust/crates/salomon-corpusd` et son client Python
optionnel dans `fuzz_orchestrator/native_corpus.py`. Il s'active avec
`engine.corpus_backend = "rust"`, utilise des lots et revient automatiquement
au backend Python si le helper est absent ou tombe en panne. Le protocole de
contrôle distribué est dans `proto/salomon.proto`.

Le protocole gRPC ne doit pas transporter chaque cas dans le hot path. Un worker
exécute localement une boucle complète et échange périodiquement des deltas de
corpus, de couverture, de findings et de statistiques.

## Principes

1. **Compatibilité avant réécriture** : `fuzz.toml` et
   `python -m fuzz_orchestrator ...` restent supportés.
2. **Hot path local** : canaux mémoire ou IPC local ; jamais de gRPC par entrée.
3. **Données adressées par hash** : corpus et artefacts peuvent être dédupliqués.
4. **Backends explicites** : builtin, AFL++, libFuzzer et futurs forkserver ou
   QEMU sont interchangeables derrière une interface.
5. **Sécurité par défaut** : réseau désactivé, allow-list obligatoire, limites
   de taille/temps et commandes sans shell.
6. **Versionnement** : `schema_version = 1` pour `Salomon.toml` et package
   `salomon.v1` pour le contrôle distribué.

## Vérifier la base SALOMON

```bash
python3 -m fuzz_orchestrator validate configs/Salomon.toml
python3 -m fuzz_orchestrator fuzz --config configs/Salomon.toml --limit 20
```

Quand Rust sera disponible :

```bash
cargo test --manifest-path rust/Cargo.toml
```

Le premier composant Rust à remplacer sera le Corpus Manager/Scheduler. Le
reste du moteur Python pourra continuer à servir de référence comportementale
pendant la migration.
