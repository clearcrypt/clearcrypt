# Benchmarks mémoire et débit de ClearCrypt V2

Ce protocole mesure `CFENC002` sur Node.js. Il sert à comparer les tailles de
bloc et les environnements. Il ne qualifie pas encore les tailles de fichier de
1, 10 et 100 Go, qui relèvent de V2-017.

## Commande reproductible

Construire le package, puis lancer le benchmark avec Node.js 24 ou supérieur :

```sh
npm run build
npm run benchmark:v2
```

La configuration par défaut traite 128 Mio, compare des blocs de 1, 4 et 8 Mio,
effectue un échauffement et conserve trois mesures. Une campagne plus longue
peut être lancée ainsi :

```sh
npm run benchmark:v2 -- --size-mib 1024 --runs 5 --warmups 1
```

Pour isoler un type de destination ou réduire la campagne :

```sh
npm run benchmark:v2 -- --scenario instrumented --chunk-sizes-mib 4
npm run benchmark:v2 -- --scenario files --chunk-sizes-mib 1,4,8
```

Le résultat JSON doit être conservé avec le rapport de test. Il contient la
date, la version de Node.js, le système, le processeur, le nombre de processeurs
logiques, la mémoire physique visible et tous les paramètres du protocole.

## Mesures séparées

Chaque ligne est exécutée dans un nouveau processus avec `--expose-gc` afin
qu'un essai précédent ne fixe pas le pic mémoire du suivant.

Le rapport contient trois groupes :

- `kdf` mesure Argon2id seul avec le profil V2 indiqué dans le résultat, en
  distinguant le premier appel à froid des mesures après échauffement ;
- `io` mesure une copie sans chiffrement, du fichier vers un compteur puis du
  fichier vers un autre fichier ;
- `data` mesure le pipeline V2 avec une KEK fixe injectée par l'entrée interne
  réservée au benchmark. Argon2id est donc absent de ces durées.

La destination `instrumented` compte les octets sans les conserver. Pour le
chiffrement, la source est générée progressivement par morceaux de 256 Kio.
Pour le déchiffrement, une archive valide préparée hors mesure est lue depuis un
fichier, puis le clair est envoyé au compteur. La destination `files` mesure le
parcours complet fichier vers fichier. Les fichiers temporaires sont supprimés
après chaque processus.

Les résultats `io` permettent d'observer le coût de lecture et d'écriture du
support utilisé. Il ne faut pas les soustraire mécaniquement des durées du
pipeline : le cache du système et l'ordonnancement des opérations peuvent être
différents.

## Données et mémoire

Les données sources sont générées progressivement et aucun fichier complet
n'est construit dans un `Uint8Array`. Pour chaque opération, le rapport publie :

- les durées individuelles, la médiane, le p95, le minimum et le maximum ;
- le débit calculé depuis la médiane et le volume réellement traité ;
- le RSS et la mémoire `arrayBuffers` au départ, au pic observé et leur écart ;
- la taille de bloc, le type de destination et le résultat de la vérification.

Le chiffrement vers fichier est relu et authentifié après la mesure. Le fichier
déchiffré et la copie d'E/S sont comparés au fichier source par SHA-256. Les
destinations instrumentées vérifient le nombre exact d'octets.

L'échantillonnage mémoire a lieu toutes les 2 ms. `process.memoryUsage()` reste
une observation du processus Node.js : le RSS inclut le runtime, WebAssembly et
les bibliothèques natives, tandis que `arrayBuffers` ne représente pas toute la
mémoire du processus.

## Interprétation

Argon2id est un coût fixe payé une fois par opération. Les lignes `data` et
`io` sont proportionnelles au volume. Le temps total attendu pour une opération
réelle comprend le KDF, le pipeline et les attentes du support d'entrée/sortie.

Les débits publiés sont uniquement les mesures de la machine décrite dans le
JSON. Le runner ne projette pas une durée pour un fichier plus grand et
n'applique aucun seuil de performance en CI, car les machines hébergées n'ont
pas une charge ni des caractéristiques stables.

Pendant une campagne de référence, utiliser le même mode d'alimentation,
fermer les applications lourdes, relever les contraintes thermiques et noter le
type de stockage ainsi que l'emplacement du répertoire temporaire du système.
