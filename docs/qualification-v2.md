# Qualification des grands volumes ClearCrypt V2

Cette qualification vérifie le débit, la mémoire bornée et l'intégrité de
`CFENC002`. Elle regroupe le protocole de benchmark et les résultats de la
campagne sur grands volumes.

## Benchmark reproductible

Après construction, le benchmark Node.js 24 compare par défaut des blocs de 1,
4 et 8 Mio sur 128 Mio de données, avec un échauffement et trois mesures :

```sh
npm run build
npm run benchmark:v2
npm run benchmark:v2 -- --size-mib 1024 --runs 5 --warmups 1
```

`--scenario instrumented` utilise une destination qui compte les octets sans
les conserver. `--scenario files` mesure un parcours fichier vers fichier. Le
rapport JSON distingue :

- Argon2id, coût fixe payé une fois par opération ;
- les E/S brutes, sans chiffrement ;
- le pipeline V2 avec une KEK fixe réservée au benchmark, donc sans Argon2id.

Chaque mesure tourne dans un nouveau processus avec `--expose-gc`. Le rapport
donne les durées, médiane, p95, débit, RSS et mémoire `arrayBuffers`. Les sources
sont produites progressivement et les sorties sont vérifiées par longueur,
authentification ou SHA-256. Les E/S ne doivent pas être soustraites
mécaniquement du pipeline : le cache système et l'ordonnancement diffèrent.

Les résultats décrivent seulement la machine indiquée. Aucun seuil de débit
n'est imposé en CI et aucune durée extrapolée n'est présentée comme une mesure.

## Protocole Node.js

Après construction du package :

```sh
npm run build
npm run qualify:node:v2
```

Le runner génère le clair progressivement par morceaux de 256 Kio, utilise des
blocs chiffrés de 4 Mio et calcule SHA-256 pendant la lecture et la restauration.
Il ne construit jamais le clair ou l'archive complète dans un `Uint8Array`.

Par défaut, 1 et 10 Gio utilisent une archive temporaire réelle. Le test de
100 Gio relie directement le chiffrement au déchiffrement par un
`TransformStream` borné afin de protéger les postes qui n'ont pas assez
d'espace. La limite peut être relevée explicitement lorsque le disque conserve
la réserve demandée. La campagne publiée a ainsi également validé une archive
réelle de 100 Gio avec `--file-up-to-gib 100`.

Le mode fichier est sélectionné jusqu'à `--file-up-to-gib` si l'espace libre
permet de conserver le volume demandé et la réserve configurée :

```sh
npm run qualify:node:v2 -- --sizes-gib 1,10,100 --file-up-to-gib 10 --reserve-gib 16
```

Chaque résultat contient durée, débit, RSS, mémoire `arrayBuffers`, hash et
configuration de la machine. L'archive temporaire est supprimée après sa
validation.

## Résultats Node.js du 4 octobre 2026

Environnement : Node.js 24.15.0 dans Docker/WSL2, Intel Core i5-11600K,
12 processeurs logiques, environ 16 Gio de mémoire visible et 128,96 Gio libres
sur le volume de qualification. Le profil Argon2id utilisait 64 Mio, deux
passes et un parallélisme de deux.

| Volume | Parcours | Chiffrement | Déchiffrement | Pic RSS | Intégrité |
| --- | --- | ---: | ---: | ---: | --- |
| 1 Gio | archive réelle | 160,38 Mio/s | 166,04 Mio/s | 214,00 Mio | SHA-256 identique |
| 10 Gio | archive réelle | 136,00 Mio/s | 190,26 Mio/s | 216,09 Mio | SHA-256 identique |
| 100 Gio | archive réelle | 162,88 Mio/s | 164,72 Mio/s | 220,41 Mio | SHA-256 identique |

Le pic RSS reste du même ordre entre 1 et 100 Gio. Un contrôle supplémentaire
de 100 Gio dans un tube borné a aussi réussi en 278,4 secondes, avec un débit
de bout en bout de 367,81 Mio/s et un pic RSS de 254,16 Mio. Ce résultat
complémentaire ne mesure pas le stockage. Le rapport machine lisible est conservé dans
[qualification-v2-node-2026-10-04.json](results/qualification-v2-node-2026-10-04.json).

## Annulation et erreurs d'écriture

Le runner vérifie avant la campagne :

- l'annulation en cours de traitement, classée `ABORTED`, avec source annulée
  et destination interrompue ;
- une écriture simulant `ENOSPC` ;
- une écriture simulant `EIO`.

Les deux erreurs d'écriture arrêtent immédiatement la lecture et ne produisent
pas de succès. L'API de flux générique les classe actuellement `INTERNAL` ; un
adaptateur d'application doit donc conserver la cause ou traduire les erreurs
de sa destination. L'adaptateur de fichiers Node expose déjà
`ClearcryptFileOutputError`. Cette limite doit rester visible dans la
documentation publique.

## Qualification navigateur desktop

La campagne navigateur est volontairement séparée :

```sh
npm run build
npm run qualify:browser:v2 -- --size-mib 64
```

Elle réalise dans un Web Worker un round trip borné avec blocs de 4 Mio, source
de 64 Kio, destination sans accumulation et contrôle d'intégrité. La page doit
rester réactive et une seule écriture peut être active.

Le 4 octobre 2026, **64 Mio ont réussi sur Chromium, Firefox et WebKit** dans
l'image Playwright 1.61.1 sous Linux. Les 33 tests navigateur ont réussi. Les
API utilisées par ce banc ne fournissent pas une mesure mémoire portable du
Worker ; aucune valeur de mémoire navigateur n'est donc inventée.

## Limites desktop et mobile

La qualification Node.js couvre des archives réelles de 1, 10 et 100 Gio sur
le poste décrit. La capacité à sauvegarder 100 Gio reste dépendante de l'espace
libre, du débit et des erreurs propres au support de destination de l'utilisateur.

Les navigateurs desktop sont qualifiés ici à 64 Mio dans un environnement
automatisé. Cette valeur prouve le parcours Worker borné ; elle ne constitue
pas encore une promesse multi-Go dans un navigateur réel.

Aucun appareil Android ou iPhone physique n'a été testé pendant cette
campagne. ClearCrypt V2 ne publie donc pour l'instant aucune taille maximale
qualifiée sur mobile. Les essais mobiles devront relever le navigateur, le
modèle, la mémoire, la destination progressive disponible, le mode
d'alimentation et les contraintes thermiques.
