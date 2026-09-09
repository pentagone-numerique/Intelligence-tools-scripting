# Stratégie d'instrumentation

## Ordre d'intégration recommandé

1. Réutiliser AFL++ instrumentation et libFuzzer comme backends externes.
2. Supporter SanitizerCoverage pour les cibles LLVM contrôlées.
3. Ajouter une runtime SALOMON qui expose une bitmap d'edges et un compteur
   de nouveautés.
4. Ajouter des profils QEMU/Frida optionnels pour les binaires sans source.

## Bitmap initiale

La première compatibilité peut utiliser une bitmap de 65 536 octets, comme le
contrat `COVERAGE_MAP_SIZE` dans `salomon-core`. Une runtime instrumentée doit
:

- remettre la bitmap à zéro avant chaque exécution ;
- enregistrer les transitions d'edges ;
- produire un hash de bitmap et un delta d'edges ;
- signaler les edges rares et nouveaux au Corpus Manager.

Il faut éviter d'écrire une passe LLVM propriétaire avant d'avoir validé ce
contrat avec des programmes instrumentés par SanitizerCoverage.

## Sanitizers

Les profils doivent être séparés :

- ASan + UBSan pour la campagne mémoire principale ;
- MSan dans une build dédiée avec toutes les dépendances instrumentées ;
- TSan dans une campagne dédiée aux accès concurrents.

Les rapports sanitizer sont normalisés en `BugReport` et dédupliqués par une
signature stable incluant le type, le point de crash et une empreinte de stack.
