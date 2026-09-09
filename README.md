# Fuzz Orchestrator

Un orchestrateur de fuzzing extensible, écrit en Python 3.11 et sans dépendance externe. Il permet de lancer une campagne reproductible contre :

- un binaire local via `stdin`, un fichier temporaire ou un argument ;
- un service TCP ;
- un service UDP ;
- une URL HTTP/HTTPS avec l’entrée dans le corps, la query string ou un header ;
- des échanges TCP/UDP multi-trames pour les protocoles avec état ;
- du fuzzing différentiel entre deux implémentations ;
- replay et minimisation automatique des findings ;
- délégation optionnelle à AFL++, libFuzzer ou une commande de fuzzing externe ;
- pacing réseau, déduplication des findings et index SQLite pour les campagnes longues.

Le projet est volontairement **safety-first** : les cibles réseau sont désactivées par défaut, exigent une allow-list explicite, les commandes binaires ne passent jamais par un shell, et les entrées/sorties sont plafonnées.

> À utiliser uniquement sur des binaires et services que vous possédez ou que vous êtes explicitement autorisé à tester.

## Démarrage rapide

Le module fonctionne directement depuis le dépôt :

Le nom SALOMON est introduit sans casser l'ancien CLI. Les deux formats sont
acceptés ; `Salomon.toml` est traduit vers le moteur actuel à la frontière de
configuration.

```bash
python3 -m fuzz_orchestrator init Salomon.toml --format salomon --kind binary
python3 -m fuzz_orchestrator validate Salomon.toml
python3 -m fuzz_orchestrator fuzz --config Salomon.toml --limit 100
# Après installation du package :
# salomon fuzz --target ./mon_binaire --input ./seeds/
```

Le Corpus Manager Rust peut être activé explicitement dans `Salomon.toml` :

```toml
[engine]
backend = "builtin"
corpus_backend = "rust"
corpus_command = ["salomon-corpusd"]
corpus_batch_size = 32
```

Le backend Python reste le fallback si `salomon-corpusd` n'est pas disponible.

```bash
python3 -m fuzz_orchestrator init fuzz.toml --kind binary
# Modifier target.command pour pointer vers le programme à tester.
python3 -m fuzz_orchestrator validate fuzz.toml
python3 -m fuzz_orchestrator run fuzz.toml --dry-run
python3 -m fuzz_orchestrator run fuzz.toml --limit 100 --verbose
```

Une commande installable est aussi déclarée dans `pyproject.toml` :

```bash
python3 -m pip install -e .
fuzz-orchestrator run fuzz.toml --limit 100
```

Un exemple de cible locale est disponible dans `examples/targets/demo_binary.py`.

Le socle de migration SALOMON est documenté dans `docs/architecture.md`, avec
les contrats Rust dans `rust/crates/salomon-core`, le Corpus Manager/Scheduler
natif dans `rust/crates/salomon-corpus`, le pont IPC local dans
`rust/crates/salomon-corpusd` et le protocole de contrôle futur dans
`proto/salomon.proto`.

## Configuration TOML

La configuration est résolue par rapport au répertoire du fichier TOML :

```toml
[run]
name = "parser-local"
iterations = 1000
workers = 1
timeout_seconds = 1.0
max_input_size = 1048576
seed = 1337
output_dir = "artifacts"
save_all_inputs = false
stop_on_finding = false
scheduler = "feedback" # random ou feedback
# Réseau uniquement : limite globale partagée entre les workers.
# max_requests_per_second = 10

[corpus]
paths = ["seeds"]
inline = ["hello", "version=1\n"]

[mutations]
operations = ["bitflip", "byteflip", "arith8", "insert", "delete", "duplicate", "dictionary", "splice"]
max_operations = 8
dictionary = ["\r\n", "{}", "null"]

[engine]
type = "builtin"

[target]
type = "binary"
command = ["python3", "examples/targets/demo_binary.py"]
input_mode = "stdin"
expected_exit_codes = [0]
max_output_bytes = 65536
# Optionnel, sur Linux avec resource.prlimit : limite d'espace d'adressage (MiB).
# max_memory_mb = 512

[safety]
allow_network = false
allowed_hosts = ["127.0.0.1", "localhost", "::1"]
max_response_bytes = 65536
```

Pour un binaire qui lit un chemin de fichier :

```toml
[target]
type = "binary"
command = ["./mon-parser", "--input", "{input}"]
input_mode = "file"
```

Le placeholder `{input}` est remplacé par un chemin temporaire différent à chaque cas. Pour une entrée texte en argument, utiliser `input_mode = "argv"`. Les commandes sont des tableaux d’arguments, jamais des chaînes shell.

### Fuzzing différentiel

Deux cibles peuvent recevoir exactement les mêmes entrées pour détecter une divergence entre deux versions ou implémentations :

```toml
[target]
type = "differential"

[target.left]
type = "binary"
command = ["./parser-stable"]
input_mode = "stdin"

[target.right]
type = "binary"
command = ["./parser-new"]
input_mode = "stdin"
```

Le moteur classe les cas en `divergence` lorsque les statuts, codes de retour, réponses ou sorties diffèrent. Un crash partagé reste classé `shared_finding`. Les deux sous-cibles peuvent aussi être TCP, UDP ou HTTP, avec les mêmes règles d’autorisation réseau.

### Moteurs externes et vraie couverture

Pour déléguer la génération et l’instrumentation à un moteur installé localement, remplacer le moteur intégré :

```toml
[engine]
type = "aflpp"
executable = "afl-fuzz"
duration_seconds = 300
extra_args = []

[target]
type = "binary"
command = ["./mon-parser", "{input}"]
input_mode = "file"
```

L’adaptateur AFL++ prépare un corpus borné, remplace `{input}` par `@@`, lance `afl-fuzz` sans shell et récupère `crashes/` et `hangs/` dans le dossier de run. La cible doit être compilée avec une instrumentation AFL++ compatible.

Pour libFuzzer :

```toml
[engine]
type = "libfuzzer"
duration_seconds = 300
extra_args = ["-detect_leaks=1"]

[target]
type = "binary"
command = ["./mon-harness-libfuzzer"]
input_mode = "stdin"
```

Un moteur personnalisé peut utiliser `type = "command"` avec les placeholders `{corpus}`, `{output}` et `{duration}`. Ces moteurs externes contrôlent leur propre couverture ; `replay` et `minimize` restent réservés au moteur intégré. `--limit` est remplacé par `engine.duration_seconds`.

### Cibles réseau

Une cible réseau doit avoir **les deux** protections suivantes :

```toml
[safety]
allow_network = true
allowed_hosts = ["127.0.0.1"]

[target]
type = "tcp"
host = "127.0.0.1"
port = 9001
expect_response = true
response_timeout_is_failure = false
# Optionnel : plusieurs trames sur la même connexion TCP.
frames = ["HELLO\n", "{input}", "QUIT\n"]
```

`frames` permet de fuzzer des protocoles avec état : chaque chaîne est encodée en UTF-8 et `{input}` est remplacé par les octets mutés. Le même champ est disponible pour UDP ; au moins une trame doit contenir `{input}`.

Les hôtes doivent correspondre exactement à l’allow-list ou à un CIDR explicitement écrit. Les wildcards ne sont pas acceptés. Pour HTTP :

```toml
[safety]
allow_network = true
allowed_hosts = ["127.0.0.1"]

[target]
type = "http"
url = "http://127.0.0.1:8080/parse"
method = "POST"
input_location = "body" # body, query ou header
headers = { Content-Type = "application/octet-stream" }
```

Les redirections HTTP ne sont pas suivies et les proxies d’environnement sont désactivés. Il faut donc autoriser explicitement la destination voulue avant de lancer la campagne.

Pour les moteurs externes, le dossier de run contient également `corpus/`, `engine-output/`, `engine.stdout` et `engine.stderr`. Les crashes AFL++/libFuzzer sont comptés à partir des artefacts écrits dans `engine-output`.

## Rejouer et minimiser un finding

Un finding peut être rejoué sans relancer toute la campagne :

```bash
python3 -m fuzz_orchestrator replay fuzz.toml artifacts/.../findings/case-00000042.bin
```

Le réducteur applique un delta-debugging et conserve le statut observable du finding :

```bash
python3 -m fuzz_orchestrator minimize fuzz.toml artifacts/.../findings/case-00000042.bin \
  --max-attempts 500
```

Il produit `case-00000042.min.bin` et un rapport JSON. Les erreurs de transport et les cibles injoignables sont refusées afin d’éviter de créer un faux finding vide.

Chaque résultat contient aussi une signature de **comportement observable** et un marqueur de nouveauté. Ce n’est pas de la couverture de code instrumentée : cela fonctionne également pour TCP/UDP/HTTP et sert à repérer de nouvelles classes de réponses, de statuts ou de sorties. Avec `scheduler = "feedback"`, les entrées qui produisent un comportement nouveau rejoignent le corpus de travail pour les cas suivants. Pour une reproductibilité maximale, utiliser `workers = 1`; avec plusieurs workers, l’ordre d’enrichissement dépend de l’arrivée des réponses. Une intégration AFL++, libFuzzer ou SanitizerCoverage pourra être ajoutée comme backend de feedback dédié.

## Résultats

Chaque exécution crée un dossier horodaté sous `run.output_dir` :

```text
artifacts/parser-local-20260909T120000Z/
├── manifest.json       # configuration et nombre de seeds
├── results.jsonl       # format portable, un résultat par cas
├── results.sqlite3     # index local pour le dashboard
├── summary.json
└── findings/
    ├── case-00000042.bin
    ├── case-00000042.json
    ├── case-00000042.stdout
    └── case-00000042.stderr
```

Les entrées ne sont conservées que pour les findings, sauf si `save_all_inputs = true`. Chaque finding contient le seed reproduisible (`case_seed`), l’index du corpus, le SHA-256 de l’entrée et les sorties capturées. Les findings sont aussi marqués comme uniques ou dupliqués selon leur signature observable.

Statuts principaux :

- `ok` : code de sortie attendu ou réponse réseau non-fautive ;
- `crash` : processus terminé par un signal ;
- `nonzero_exit` : code de sortie inattendu ;
- `timeout` : limite de temps dépassée ;
- `server_error` : réponse HTTP 5xx ;
- `divergence` : comportement différent entre deux sous-cibles ;
- `shared_finding` : finding présent sur les deux sous-cibles ;
- `connection_error` / `error` : erreur de transport ou d’exécution.

Le CLI retourne `0` sans finding, `1` si la campagne a trouvé un cas non-OK, et `2` pour une configuration invalide.

## Dashboard local

Après une campagne, lancer le tableau de bord sans dépendance externe :

```bash
python3 -m fuzz_orchestrator dashboard artifacts/parser-local-20260909T120000Z
```

Il affiche les compteurs, les statuts, les comportements nouveaux, l’activité récente, les findings et les liens vers les artefacts. La page se rafraîchit automatiquement toutes les cinq secondes et peut aussi suivre un run encore en cours.

Le serveur écoute uniquement sur `127.0.0.1` par défaut. Pour un accès depuis un réseau de laboratoire explicitement maîtrisé :

```bash
python3 -m fuzz_orchestrator dashboard artifacts/<run> --host 0.0.0.0 --port 8765
```

L’interface ne sert que les fichiers du dossier du run, bloque les chemins traversant (`..`) et refuse les artefacts de plus de 64 MiB.

## Tests

```bash
python3 -m unittest discover -v
python3 -m compileall -q fuzz_orchestrator tests
```

L’architecture sépare le chargement de configuration, les mutations, les adaptateurs de cibles et le moteur de campagne. De nouveaux adaptateurs peuvent être ajoutés dans `fuzz_orchestrator/targets.py` sans modifier le format des résultats.
