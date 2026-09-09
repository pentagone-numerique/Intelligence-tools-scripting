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
Base64, sans JSON ni ambiguïté d'échappement. Le token `~` représente une valeur
binaire vide, car une ligne découpée par espaces ne peut pas transporter un
champ Base64 vide.

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

ADD_BATCH <count> <parent-id|-> <base64> ...
BATCH <count>
ENTRY ...
END BATCH

NEXT
NONE

NEXT_BATCH <count>
BATCH <count>
ENTRY ...
END BATCH

FEEDBACK <id> <energy> <favored> <new-edges> <interesting> <hash|->
OK FEEDBACK

FEEDBACK_BATCH <count> <id> <energy> <favored> <new-edges> <interesting> <hash|-> ...
OK FEEDBACK_BATCH

STATS
STATS <entries> <bytes> <max-entries> <max-bytes>

QUIT
BYE
```

Les erreurs sont renvoyées ainsi :

```text
ERR <code> <base64-message>
```

Le helper ne doit pas être exposé sur le réseau. L'intégration Python
optionnelle l'utilise par lots pour l'amorçage, le préfetch des seeds et le
feedback ; le backend Python reste le fallback automatique. Une future FFI
in-process pourra encore réduire le coût local avant d'envisager une boucle
native complète.
