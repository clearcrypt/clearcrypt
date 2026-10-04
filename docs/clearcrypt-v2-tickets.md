# ClearCrypt v2 : découpage en tickets

Date : 3 octobre 2026. Statut : proposition de plan d'implémentation.

Ce document découpe la prise en charge des fichiers volumineux en changements courts et vérifiables. La cible est un nouveau format `CFENC002` traité en streaming, tout en conservant intégralement la lecture, l'écriture et l'API de `CFENC001`.

La capacité recherchée est le traitement de fichiers allant de 1 Go à environ 100 Go avec une consommation mémoire bornée. ClearCrypt reste uniquement responsable du chiffrement et du déchiffrement. Le stockage, l'envoi réseau et les services utilisant la bibliothèque restent hors du package.

## Règles communes aux tickets

Chaque ticket doit :

- conserver tous les tests v1 existants ;
- ajouter uniquement les exports publics nécessaires à son périmètre ;
- documenter toute décision qui devient normative pour `CFENC002` ;
- imposer des bornes avant toute allocation provenant d'une archive non fiable ;
- éviter toute accumulation proportionnelle à la taille totale du fichier ;
- inclure des tests ciblés sur le comportement ajouté ;
- rester fusionnable indépendamment des tickets suivants.

Les performances multi-Go ne doivent pas être simulées avec un unique buffer en mémoire. Les générateurs, lecteurs et destinations de test doivent produire et consommer les données progressivement.

## Vue d'ensemble

| Ordre | Ticket | Résultat principal | Dépend de |
| ---: | --- | --- | --- |
| 1 | V2-001 | Périmètre, menaces et décisions d'API | — |
| 2 | V2-002 | Spécification binaire provisoire `CFENC002` | V2-001 |
| 3 | V2-003 | Revue de la construction cryptographique | V2-002 |
| 4 | V2-004 | Types, constantes et codecs des structures v2 | V2-003 |
| 5 | V2-005 | Lecteur incrémental borné | V2-004 |
| 6 | V2-006 | Writer incrémental et destination de test | V2-004 |
| 7 | V2-007 | Chiffrement authentifié d'un bloc | V2-004 |
| 8 | V2-008 | Déchiffrement authentifié d'un bloc | V2-007 |
| 9 | V2-009 | Pipeline complet de chiffrement v2 | V2-005 à V2-007 |
| 10 | V2-010 | Pipeline complet de déchiffrement v2 | V2-005, V2-006, V2-008 |
| 11 | V2-011 | API publique, progression et annulation | V2-009, V2-010 |
| 12 | V2-012 | Adaptateur de fichiers et CLI Node | V2-011 |
| 13 | V2-013 | Exécution navigateur et Web Worker | V2-011 |
| 14 | V2-014 | Vecteurs normatifs et vérificateur indépendant | V2-011 |
| 15 | V2-015 | Tests adversariaux et propriétés | V2-011 |
| 16 | V2-016 | Benchmarks mémoire et débit | V2-012, V2-013 |
| 17 | V2-017 | Qualification 1, 10 et 100 Go | V2-014 à V2-016 |
| 18 | V2-018 | Documentation et préparation de publication | V2-017 |

Les tickets V2-005, V2-006 et V2-007 peuvent avancer séparément une fois le format et la construction cryptographique approuvés. Les tickets Node et navigateur peuvent également avancer séparément après stabilisation de l'API publique.

## Phase A — Décisions avant implémentation

### V2-001 — Définir le périmètre, les menaces et l'API de flux

**Statut : terminé le 4 octobre 2026.** Décisions consignées dans [ClearCrypt v2 : périmètre et contrat de l'API de streaming](design-v2-streaming-api.md).

**Objectif**

Définir ce que garantit la première version de `CFENC002` et ce qu'elle ne prend pas encore en charge.

**Travail**

- décrire les garanties de confidentialité, d'intégrité, d'ordre et de détection de troncature ;
- décider de l'abstraction publique de source et de destination ;
- définir la contre-pression, l'annulation et le signalement de progression ;
- définir le comportement d'une destination partiellement écrite après une erreur ;
- fixer le périmètre initial : traitement séquentiel, sans accès aléatoire ni reprise après interruption ;
- préciser que la v1 reste inchangée.

**Critères d'acceptation**

- une note de décision présente la signature envisagée de l'API ;
- le cycle de vie succès, erreur et annulation est décrit ;
- aucune décision ne dépend d'un fournisseur de stockage ou d'une application particulière ;
- les éléments hors périmètre sont explicitement listés.

### V2-002 — Rédiger la spécification binaire provisoire `CFENC002`

**Statut : brouillon terminé le 4 octobre 2026.** Framing consigné dans [ClearCrypt encrypted archive format V2](format-v2.md), puis amendé par la revue V2-003.

**Objectif**

Décrire chaque octet du nouveau format avant d'implémenter le parseur ou le chiffrement.

**Travail**

- définir le magic, la version et les identifiants d'algorithmes ;
- définir l'en-tête, l'enveloppe de clé et les paramètres Argon2id ;
- définir l'encodage des enregistrements de données et de fin ;
- utiliser des tailles et compteurs capables de représenter plus de 4 Go ;
- fixer les tailles minimales et maximales des blocs ;
- définir le traitement du fichier vide, du dernier bloc court et des octets après la fin ;
- définir les règles de compatibilité et de rejet des versions inconnues.

**Critères d'acceptation**

- `docs/format-v2.md` contient un tableau complet des champs, offsets ou règles de framing ;
- le lecteur peut connaître la taille maximale d'une allocation avant de lire le contenu correspondant ;
- un fichier vide possède une représentation valide non ambiguë ;
- une archive tronquée ne peut pas être confondue avec une archive terminée.

### V2-003 — Valider la construction cryptographique

**Statut : revue interne terminée puis amendée le 4 octobre 2026.** Construction segmentée et limites consignées dans [ClearCrypt V2 cryptographic construction review](crypto-review-v2.md). Une revue externe indépendante reste obligatoire avant la stabilisation et la publication de production.

**Objectif**

Faire approuver les règles de clés, nonces, données associées et terminaison avant leur diffusion.

**Travail**

- définir la dérivation ou la construction du nonce unique de chaque enregistrement ;
- lier chaque bloc à l'en-tête, au fichier, à son index, à son type et à sa longueur ;
- authentifier le nombre de blocs et la taille totale dans l'enregistrement final ;
- définir les domaines séparés pour les blocs de données, la fin et l'enveloppe de clé ;
- fixer le nombre maximal de blocs par segment, le budget par clé et la limite globale ;
- définir la dérivation HKDF-SHA-256 des clés de segment et de la clé FINAL ;
- faire relire la construction et intégrer les corrections dans `format-v2.md`.

**Critères d'acceptation**

- aucune paire clé/nonce ne peut être réutilisée dans une archive conforme ;
- suppression, duplication, permutation et collage de blocs sont couverts par le modèle ;
- la limite maximale normative par archive est calculée et documentée ;
- la construction a fait l'objet d'une revue distincte du code qui l'implémentera.

## Phase B — Briques internes

### V2-004 — Ajouter les types, constantes et codecs v2

**Statut : terminé le 4 octobre 2026.** Constantes, types et codecs ajoutés dans `src/v2/spec/`, avec tests unitaires des champs, limites et compteurs 64 bits.

**Objectif**

Représenter et encoder les structures fixes de `CFENC002` sans encore traiter un fichier complet.

**Travail**

- créer `src/v2/spec/` ;
- ajouter les types de l'en-tête et des enregistrements ;
- ajouter les identifiants et limites du key schedule segmenté ;
- ajouter les fonctions d'encodage et de décodage des entiers ;
- traiter les valeurs 64 bits sans perte de précision ;
- ajouter des tests unitaires pour chaque champ et chaque limite.

**Critères d'acceptation**

- tous les champs font un aller-retour exact ;
- les dépassements, valeurs réservées et longueurs incohérentes sont rejetés ;
- aucune conversion silencieuse d'un `bigint` non représentable vers `number` n'est possible ;
- aucun export v1 n'est modifié.

### V2-005 — Implémenter le lecteur incrémental borné

**Objectif**

Lire un flux découpé arbitrairement sans charger l'archive complète.

**Travail**

- accepter des morceaux d'entrée de tailles quelconques ;
- produire successivement l'en-tête et les enregistrements complets ;
- conserver uniquement les octets nécessaires à l'enregistrement en cours ;
- vérifier les longueurs avant allocation ;
- détecter fin prématurée, enregistrement inconnu et données après la fin.

**Critères d'acceptation**

- le même fichier est correctement lu octet par octet ou en gros morceaux ;
- la mémoire du parseur est bornée par la taille maximale autorisée d'un enregistrement ;
- les champs hostiles ne provoquent pas une allocation non bornée ;
- le lecteur ne réalise aucune opération cryptographique.

### V2-006 — Implémenter le writer incrémental

**Objectif**

Émettre une archive sans concaténer tous ses octets.

**Travail**

- écrire l'en-tête, les enregistrements puis la fin vers une destination abstraite ;
- respecter la contre-pression de la destination ;
- propager les erreurs d'écriture ;
- fournir une destination mémoire bornée réservée aux petits tests ;
- fournir une destination instrumentée capable de compter les octets sans les conserver.

**Critères d'acceptation**

- le writer n'accumule pas les enregistrements déjà écrits ;
- une destination lente limite naturellement la production ;
- une erreur d'écriture arrête immédiatement l'opération ;
- les octets produits respectent `format-v2.md`.

### V2-007 — Chiffrer un enregistrement de données

**Objectif**

Implémenter et tester le chiffrement authentifié d'un seul bloc conformément à la spécification.

**Travail**

- réutiliser ou isoler proprement les primitives AES-GCM existantes ;
- construire le nonce et les données associées du bloc ;
- dériver la clé du segment attendu depuis l'AMK et l'index global ;
- chiffrer un bloc vide, complet ou court selon les règles du format ;
- vérifier les bornes avant l'appel cryptographique ;
- effacer au mieux les buffers temporaires appartenant au package.

**Critères d'acceptation**

- un résultat déterministe est possible avec des entrées de test injectées ;
- changer l'index, la longueur, le type ou l'en-tête invalide l'authentification ;
- la v1 continue d'utiliser exactement son format actuel ;
- les erreurs internes sont converties dans la taxonomie publique prévue.

### V2-008 — Déchiffrer un enregistrement de données

**Objectif**

Authentifier un bloc avant de remettre son plaintext au consommateur.

**Travail**

- reconstruire le nonce et les données associées attendues ;
- vérifier le tag avant de retourner le bloc ;
- uniformiser les erreurs de mauvais mot de passe et d'altération lorsque nécessaire ;
- ne jamais exposer le plaintext d'un bloc non authentifié.

**Critères d'acceptation**

- les blocs produits par V2-007 sont déchiffrés exactement ;
- toute altération du ciphertext ou du tag échoue ;
- aucun plaintext n'est écrit pour le bloc en échec ;
- les buffers temporaires appartenant au package sont effacés au mieux.

## Phase C — Pipelines complets

### V2-009 — Construire le pipeline de chiffrement v2

**Objectif**

Lire, regrouper, chiffrer et écrire un flux complet avec une mémoire bornée.

**Travail**

- dériver la KEK Argon2id une seule fois ;
- générer et protéger une AMK par archive, puis dériver les clés de segment à la demande ;
- regrouper les morceaux de source en blocs du format ;
- écrire chaque bloc avant de lire une quantité non bornée de données supplémentaires ;
- écrire l'enregistrement final authentifié ;
- gérer le fichier vide et le dernier bloc incomplet.

**Critères d'acceptation**

- une source plus grande que la mémoire disponible peut être traitée avec une destination instrumentée ;
- la mémoire de travail ne dépend pas de la taille totale ;
- Argon2id n'est exécuté qu'une fois par archive ;
- aucune archive complète n'est construite en mémoire.

### V2-010 — Construire le pipeline de déchiffrement v2

**Objectif**

Lire, authentifier et écrire progressivement le contenu d'une archive v2.

**Travail**

- appliquer la politique de ressources avant Argon2id ;
- déverrouiller l'AMK et dériver les clés attendues à la demande ;
- imposer une séquence stricte des indices ;
- authentifier chaque bloc avant écriture ;
- valider l'enregistrement final, les totaux et l'absence de données supplémentaires ;
- distinguer bloc valide et archive complète validée.

**Critères d'acceptation**

- le round trip fonctionne pour zéro, un et plusieurs blocs ;
- une troncature après un bloc valide fait échouer l'opération complète ;
- un bloc supprimé, répété ou déplacé est rejeté ;
- le succès n'est annoncé qu'après validation de la fin.

### V2-011 — Stabiliser l'API publique v2

**Objectif**

Exposer les pipelines avec un contrat commun à Node.js et aux navigateurs.

**Travail**

- ajouter `encryptStreamV2` et `decryptStreamV2`, ou les noms validés par V2-001 ;
- exporter les types publics nécessaires depuis `src/index.ts` ;
- ajouter `AbortSignal` et une progression limitée en fréquence ;
- définir la valeur retournée après succès ;
- documenter l'état d'une destination après erreur ou annulation ;
- vérifier le build et les déclarations TypeScript Node et navigateur.

**Critères d'acceptation**

- un consommateur peut utiliser la v2 sans importer de module interne ;
- annuler arrête la lecture, la cryptographie et l'écriture dès que possible ;
- le callback de progression ne permet pas de casser la contre-pression ;
- les exports `encryptBytesV1` et `decryptBytesV1` restent inchangés.

## Phase D — Intégrations de référence

### V2-012 — Ajouter l'adaptateur de fichiers et la CLI Node

**Objectif**

Démontrer un traitement réellement streaming sur des fichiers locaux.

**Travail**

- remplacer le chemin v2 fondé sur `readFileSync` par des flux ;
- écrire vers un fichier temporaire ;
- finaliser ou renommer la sortie seulement après succès ;
- nettoyer au mieux la sortie incomplète ;
- conserver les commandes capables de lire les archives v1 ;
- ajouter l'affichage de progression sans révéler le mot de passe.

**Critères d'acceptation**

- la CLI chiffre et déchiffre un fichier supérieur à la mémoire allouée au processus ;
- une mauvaise clé ne laisse pas une sortie présentée comme valide ;
- une interruption ne remplace pas un fichier de destination existant ;
- les codes de sortie restent documentés et stables.

### V2-013 — Valider le parcours navigateur et Web Worker

**Objectif**

Prouver que le cœur v2 fonctionne dans les navigateurs supportés sans bloquer l'interface.

**Travail**

- alimenter l'API avec un `ReadableStream` ou l'adaptateur retenu ;
- exécuter Argon2id et le traitement dans un Worker ;
- éviter les copies non bornées entre la page et le Worker ;
- tester une destination progressive réelle ou instrumentée ;
- tester l'annulation et la fermeture du Worker ;
- documenter les capacités requises de l'environnement.

**Critères d'acceptation**

- Chromium, Firefox et WebKit passent les tests compatibles avec leurs capacités ;
- l'interface de test reste réactive ;
- aucun `Blob` représentant l'archive complète n'est requis par le cœur ;
- la mémoire reste bornée quand la taille simulée augmente.

## Phase E — Sécurité et interopérabilité

### V2-014 — Publier des vecteurs normatifs v2

**Objectif**

Permettre une implémentation indépendante de `CFENC002`.

**Travail**

- créer au moins un vecteur complet avec mot de passe Unicode et contenu binaire ;
- publier des intermédiaires HKDF couvrant le segment 0, une transition de segment et FINAL ;
- couvrir fichier vide, dernier bloc court et plusieurs blocs ;
- publier les valeurs intermédiaires nécessaires à la vérification ;
- créer un vérificateur qui n'importe pas l'encodeur ou le décodeur v2 de ClearCrypt ;
- vérifier Node et navigateur avec les mêmes vecteurs.

**Critères d'acceptation**

- le vérificateur indépendant reproduit et déchiffre les archives attendues ;
- modifier un octet significatif fait échouer la vérification ;
- la spécification suffit pour expliquer tous les octets des vecteurs ;
- les vecteurs sont inclus dans le package publié si cette politique est retenue.

### V2-015 — Ajouter les tests adversariaux et de propriétés

**Objectif**

Tester systématiquement le parseur et les garanties du format face aux archives hostiles.

**Travail**

- tester chaque point de troncature des petits vecteurs ;
- générer des découpages arbitraires du flux d'entrée ;
- tester longueurs extrêmes, dépassements et compteurs invalides ;
- tester suppression, duplication, permutation et collage de blocs ;
- tester données supplémentaires et absence de fin ;
- ajouter un corpus minimal reproductible pour les régressions.

**Critères d'acceptation**

- les propriétés utilisent des graines reproductibles ;
- aucun cas invalide ne retourne un succès complet ;
- aucun cas hostile ne provoque d'allocation proportionnelle à une longueur non validée ;
- les échecs conservent la taxonomie d'erreurs prévue.

## Phase F — Performances et publication

### V2-016 — Créer les benchmarks mémoire et débit

**Objectif**

Mesurer le cœur v2 sans confondre cryptographie, lecture, écriture et KDF.

**Travail**

- mesurer séparément Argon2id et le traitement des données ;
- comparer des blocs de 1, 4 et 8 Mio ;
- mesurer chiffrement et déchiffrement ;
- relever débit, durée, RSS et mémoire des `ArrayBuffer` lorsque disponible ;
- mesurer avec une destination instrumentée puis avec des fichiers réels ;
- publier le protocole, les versions et la configuration matérielle.

**Critères d'acceptation**

- les benchmarks sont reproductibles avec une commande documentée ;
- les données sont générées progressivement ;
- le résultat distingue coût fixe et coût proportionnel au volume ;
- aucune projection n'est présentée comme une mesure réelle.

### V2-017 — Qualifier les fichiers de 1, 10 et 100 Go

**Objectif**

Vérifier que l'implémentation répond au cas d'usage des grandes archives.

**Travail**

- réaliser des round trips de 1, 10 et 100 Go sur Node.js ;
- réaliser les tailles raisonnablement supportées sur chaque navigateur cible ;
- vérifier l'intégrité du résultat sans charger les fichiers en mémoire ;
- relever le pic mémoire, la durée et le débit soutenu ;
- tester annulation, espace disque insuffisant et erreur d'écriture ;
- documenter séparément desktop et mobile.

**Critères d'acceptation**

- le pic mémoire reste du même ordre entre 1 et 100 Go sur Node.js ;
- le hash du clair original et du clair restauré est identique ;
- les limites observées par environnement sont publiées ;
- aucune promesse navigateur ou mobile ne dépasse les environnements réellement testés.

### V2-018 — Finaliser la documentation et préparer la publication

**Objectif**

Publier la v2 sans casser les utilisateurs et archives v1.

**Travail**

- finaliser `docs/format-v2.md` ;
- documenter l'API, les exemples, la mémoire et les limites ;
- documenter la détection v1/v2 et la politique de compatibilité ;
- mettre à jour le README, le changelog et le contenu du package ;
- ajouter les contrôles de package et de release nécessaires ;
- préciser que la conversion v1 vers v2 nécessite un déchiffrement et un nouveau chiffrement.

**Critères d'acceptation**

- les exemples publics compilent ;
- les tests et builds v1 et v2 passent ;
- une ancienne archive v1 reste déchiffrable ;
- le package contient les spécifications et vecteurs annoncés ;
- les capacités et limites publiées correspondent aux résultats de V2-017.

## Tickets à garder pour une évolution ultérieure

Ces sujets ne doivent pas bloquer la première version streaming :

- reprise après crash ou interruption ;
- accès aléatoire à un bloc ;
- parallélisation de plusieurs blocs ;
- modification d'une archive en place ;
- masquage de la taille par padding ;
- compression intégrée ;
- conversion v1 vers v2 en streaming ;
- API de stockage ou d'envoi réseau ;
- intégration à un fournisseur cloud particulier.

Chacun de ces sujets modifie le contrat, le format ou les garanties de sécurité et doit faire l'objet d'un ticket de conception séparé.

## Ordre de livraison recommandé

La première démonstration utile arrive à la fin de V2-010 : un aller-retour streaming interne est alors possible. V2-012 fournit ensuite une preuve concrète sur fichiers volumineux avec la CLI. La v2 ne devrait être déclarée stable qu'après les vecteurs indépendants, les tests adversariaux et la qualification des performances.

