# Distribution SALOMON

La distribution est prévue comme une optimisation de campagnes longues, pas
comme une dépendance du fuzzing local.

## Rôle du master

- crée la campagne et la politique de sécurité ;
- conserve les statistiques globales ;
- déduplique les entrées par hash ;
- fusionne les deltas de couverture ;
- distribue des lots de corpus ;
- collecte les findings et les artefacts.

## Rôle d'un worker

- vérifie ses capacités et son backend ;
- garde une copie locale du corpus ;
- exécute la boucle mutation/exécution/feedback localement ;
- envoie des lots de nouveaux seeds et de nouveaux edges ;
- respecte les limites de ressources et la configuration de cible.

## Transport

`proto/salomon.proto` définit un premier contrat gRPC avec :

- `GetCapabilities` ;
- `ExecuteBatch` ;
- `PushCorpus` ;
- `SubscribeStats` ;
- `StopCampaign`.

Dans la version initiale, `ExecuteBatch` est prévu pour des tests de capacité
et des workers contrôlés. Le chemin de production doit privilégier une boucle
locale et `PushCorpus` par lots. Les flux doivent être authentifiés dans un
futur mode cluster ; ne pas exposer un worker directement sur Internet.
