# Pont IPC local du Corpus Manager

`salomon-corpusd` est un helper local optionnel. Il ne s'agit pas d'un
serveur réseau : le moteur Python le démarre avec un tableau d'arguments et
échange des trames texte sur stdin/stdout.

## Démarrage

```bash
salomon-corpusd \
  --strategy feedback \
  --seed 1337 \
  --max-entries 10000 \
  --max-bytes 67108864 \
  --max-input-bytes 1048576
```

Les commandes ne passent jamais par un shell. Le client Python correspondant
est `fuzz_orchestrator.native_corpus.NativeCorpusClient`.

## Protocole v1

Chaque requête et chaque réponse est une ligne ASCII. Les bytes sont encodés en
Base64, sans JSON ni ambiguïté d'échappement.

Requête initiale :

```text
HELLO 1
HELLO 1 salomon-corpusd
```

Commandes disponibles :

```text
PING
PONG

ADD <parent-id|-> <base64>
ENTRY <id> <parent-id|-> <energy> <favored> <base64> <new-edges> <interesting> <hash|->

NEXT
NONE

FEEDBACK <id> <energy> <favored> <new-edges> <interesting> <hash|->
OK FEEDBACK

STATS
STATS <entries> <bytes> <max-entries> <max-bytes>

QUIT
BYE
```

Les erreurs sont renvoyées ainsi :

```text
ERR <code> <base64-message>
```

Le helper ne doit pas être exposé sur le réseau. L'IPC par entrée n'est pas le
chemin par défaut du moteur : une future intégration de campagne devra
regrouper les échanges ou utiliser une FFI in-process avant d'activer ce
backend dans la boucle chaude.
