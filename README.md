# Fuzz Orchestrator

Un orchestrateur de fuzzing extensible, écrit en Python 3.11 et sans dépendance externe. Il permet de lancer une campagne reproductible contre :

- un binaire local via `stdin`, un fichier temporaire ou un argument ;
- un service TCP ;
- un service UDP ;
- une URL HTTP/HTTPS avec l’entrée dans le corps, la query string ou un header ;
- des échanges TCP/UDP multi-trames pour les protocoles avec état ;
- replay et minimisation automatique des findings.

Le projet est volontairement **safety-first** : les cibles réseau sont désactivées par défaut, exigent une allow-list explicite, les commandes binaires ne passent jamais par un shell, et les entrées/sorties sont plafonnées.

> À utiliser uniquement sur des binaires et services que vous possédez ou que vous êtes explicitement autorisé à tester.

## Démarrage rapide

Le module fonctionne directement depuis le dépôt :

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

[corpus]
paths = ["seeds"]
inline = ["hello", "version=1\n"]

[mutations]
operations = ["bitflip", "byteflip", "arith8", "insert", "delete", "duplicate", "dictionary", "splice"]
max_operations = 8
dictionary = ["\r\n", "{}", "null"]

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
├── results.jsonl       # un résultat borné par cas
├── summary.json
└── findings/
    ├── case-00000042.bin
    ├── case-00000042.json
    ├── case-00000042.stdout
    └── case-00000042.stderr
```

Les entrées ne sont conservées que pour les findings, sauf si `save_all_inputs = true`. Chaque finding contient le seed reproduisible (`case_seed`), l’index du corpus, le SHA-256 de l’entrée et les sorties capturées.

Statuts principaux :

- `ok` : code de sortie attendu ou réponse réseau non-fautive ;
- `crash` : processus terminé par un signal ;
- `nonzero_exit` : code de sortie inattendu ;
- `timeout` : limite de temps dépassée ;
- `server_error` : réponse HTTP 5xx ;
- `connection_error` / `error` : erreur de transport ou d’exécution.

Le CLI retourne `0` sans finding, `1` si la campagne a trouvé un cas non-OK, et `2` pour une configuration invalide.

## Tests

```bash
python3 -m unittest discover -v
python3 -m compileall -q fuzz_orchestrator tests
```

L’architecture sépare le chargement de configuration, les mutations, les adaptateurs de cibles et le moteur de campagne. De nouveaux adaptateurs peuvent être ajoutés dans `fuzz_orchestrator/targets.py` sans modifier le format des résultats.
