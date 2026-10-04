# ClearCrypt v2 : fichiers de plusieurs Go et limites restantes

Date : 2 octobre 2026. Statut : étude de faisabilité et proposition de conception ; aucune API ni spécification v2 n'est encore implémentée par ce document.

## Ce qu'on peut viser

**Chiffrer et déchiffrer des fichiers de plusieurs Go est réalisable.** La solution durable est de traiter le fichier progressivement, par blocs authentifiés, avec une mémoire bornée indépendante de la taille totale. Cela permet aussi d'envisager des dizaines ou centaines de Go sur des environnements adaptés.

« Infini » ne peut pas être une garantie technique : le disque, les compteurs du format, les limites cryptographiques et le temps d'exécution restent finis. Une promesse plus précise serait : **« chiffrement en streaming, sans chargement du fichier complet en mémoire, sous réserve des limites documentées du format et de l'environnement »**.

Recommandation : créer un format `CFENC002`, conserver la lecture de `CFENC001`, et viser d'abord une validation réelle à **1, 4 et 10 Gio**, sur Node.js et sur les navigateurs disposant d'une sortie adaptée. Ce sont des objectifs de qualification, pas des capacités déjà mesurées.

Conventions : 1 Go = 10⁹ octets ; 1 Gio = 2³⁰ octets ; 1 Mio = 2²⁰ octets.

## 1. D'où viennent les limites de la v1 ?

L'analyse du dépôt montre qu'il n'existe pas de constante publique limitant le fichier à un nombre précis de Mo ou Go. Le plafond actuel est appliqué dans l'intégration web Tegelis, dont le code applicatif n'est pas présent dans ce dépôt.

### Point de référence : Tegelis à 100 Mo

Au 2 octobre 2026, [Tegelis](https://tegelis.fr/) affiche une taille maximale de **100 Mo par fichier** et indique utiliser ClearCrypt 1.1.1 avec le format `CFENC001`. Le mainteneur rapporte que cette intégration fonctionne très bien avec cette limite. La consultation du site confirme le plafond affiché ; elle ne constitue pas un test de performance.

Ce retour donne un point de référence concret pour la v1. Avec une entrée de 100 Mo, le modèle ci-dessous représente environ 300 Mo de buffers au chiffrement, auxquels s'ajoutent les ressources cryptographiques et applicatives. Le bon fonctionnement observé est cohérent avec ce modèle ; les appareils et navigateurs concernés restent à consigner pour en faire une qualification reproductible.

Pour Tegelis v2, conserver les 100 Mo comme référence de comparaison et qualifier le nouveau parcours streaming à 1, 4 et 10 Gio. Le changement doit couvrir la lecture, le chiffrement **et la sauvegarde progressive du résultat**. Augmenter uniquement la validation de taille de l'interface laisserait le coût mémoire proportionnel au fichier.

| Élément actuel | Conséquence |
| --- | --- |
| `encryptBytesV1` / `decryptBytesV1` : `Uint8Array` en entrée et en sortie | Entrée et résultat doivent tenir entièrement en mémoire. |
| Un seul appel WebCrypto AES-GCM pour tout le contenu | Le moteur doit traiter un buffer de la taille du fichier. |
| `Writer.concat()` construit l'archive finale | Le chiffrement conserve plusieurs buffers volumineux simultanément. |
| CLI : `readFileSync`, puis `new Uint8Array(input)` | Lecture intégrale et copie supplémentaire de l'entrée. |
| Une seule balise d'authentification à la fin de `CFENC001` | L'intégrité du contenu complet n'est confirmée qu'à la fin. |
| Politique `maxMemoryCostKiB` | Limite Argon2, pas la taille du fichier ni la mémoire totale. |

Le modèle documenté est approximativement **3 × la taille du fichier au chiffrement**, et **2 × au déchiffrement**, plus les coûts du runtime et d'Argon2. Pour 4 Gio, cela représente environ 12 Gio et 8 Gio de buffers visibles respectivement, avant les éventuelles copies internes. La CLI ajoute encore une copie d'entrée ; le pic effectif dépend de la durée de vie des buffers et du ramasse-miettes. Ce sont des estimations, pas des plafonds garantis. Voir [le modèle mémoire v1](memory-v1.md).

Un Web Worker maintient l'interface réactive, mais ne supprime pas ces allocations. Les limites des `ArrayBuffer`, du processus et de l'appareil peuvent faire échouer l'opération bien avant la limite théorique du chiffrement.

Le format v1 ne possède pas de champ de longueur du contenu sur 32 bits : **il n'y a donc pas ici un simple champ à élargir pour passer les 4 Go**. Les champs `u32be` existants concernent les paramètres Argon2. Voir [la spécification v1](format-v1.md).

## 2. Options possibles

| Option | Intérêt | Limites | Avis |
| --- | --- | --- | --- |
| Augmenter un plafond UI en gardant la v1 | Modification rapide pour des appareils puissants | Toujours plusieurs fois la taille en RAM ; pas de garantie multi-Go portable | Mesure temporaire uniquement, après tests locaux. |
| Optimiser les copies v1 | Réduit le pic mémoire, notamment dans la CLI | Ne change pas l'API à buffers complets | Utile, insuffisant pour la v2. |
| Streaming AES-GCM d'un seul message via `node:crypto` | Peut produire/lire du v1 avec une mémoire de travail bornée sur Node | Pas d'équivalent incrémental dans WebCrypto ; authentification globale tardive ; taille GCM finie | Pont éventuel pour les archives v1. |
| Format v2 avec AES-GCM indépendant par bloc | Compatible avec WebCrypto et Node ; mémoire bornée ; vérification progressive | Nouveau protocole à spécifier et auditer ; nonces, ordre et terminaison à sécuriser | **Option recommandée pour ClearCrypt.** |
| Format v2 utilisant libsodium `secretstream` | Construction existante pour les flux authentifiés, avec terminaison et renouvellement de clé | Dépendance et intégration WASM supplémentaires ; autre algorithme de contenu ; format à documenter | Alternative sérieuse à comparer avant de figer la spécification. |

Node fournit des objets `Cipheriv` / `Decipheriv` utilisables en streaming. Leur sortie déchiffrée peut précéder la validation de l'authenticité : un pont v1 doit donc retenir le résultat dans une destination temporaire protégée jusqu'à validation finale, ou effectuer une stratégie de vérification préalable appropriée. Voir [la documentation crypto Node.js 24](https://nodejs.org/docs/latest-v24.x/api/crypto.html#class-decipheriv).

La construction [`secretstream` de libsodium](https://doc.libsodium.org/secret-key_cryptography/secretstream) fournit notamment une balise finale et des mécanismes de renouvellement de clé. Elle réduit la conception cryptographique à inventer, mais ne dispense pas de définir le conteneur, l'enveloppe mot de passe et les règles de lecture.

## 3. Architecture v2 proposée

### Traitement de bout en bout

```text
Source fichier / flux
    → lecture et regroupement en blocs de taille bornée
    → chiffrement ou déchiffrement authentifié de chaque bloc
    → écriture progressive vers une destination
    → vérification de fin et confirmation du succès
```

Conserver Argon2id pour dériver la clé protégeant la clé de données aléatoire du fichier. **Argon2 s'exécute une fois par opération sur le fichier**, pas une fois par bloc. Les profils actuels utilisent 64 ou 128 Mio ; le streaming ne supprime pas ce coût initial.

Tester des blocs de **1 à 8 Mio**, avec 4 Mio comme point de départ. Imposer une taille maximale de bloc acceptée par le lecteur avant toute allocation. La taille annoncée dans une archive non fiable ne doit jamais décider librement de l'allocation.

Une implémentation séquentielle devrait avoir une mémoire de travail de l'ordre de quelques blocs, plus Argon2 et les coûts du runtime. Avec des blocs de 4 Mio, viser quelques dizaines de Mio pour les buffers de traitement, en plus du KDF, est raisonnable **mais reste à mesurer**. La consommation ne doit plus croître proportionnellement à la taille du fichier.

La contre-pression (*backpressure*) est indispensable : attendre que la destination accepte les données avant de poursuivre. Ne pas accumuler les blocs dans un tableau, un `Blob` final ou une file de promesses illimitée. Le découpage des lectures du flux ne correspond pas nécessairement aux blocs du format ; le lecteur doit gérer les lectures partielles.

### Format et garanties à définir avant le code

Le schéma envisagé est un en-tête versionné, une suite d'enregistrements chiffrés et un enregistrement final authentifié. Ce schéma **n'est pas une spécification cryptographique normative**.

Les règles indispensables sont :

- **En-tête authentifié** : version, algorithmes, paramètres KDF, taille des blocs, enveloppe de clé et contexte du fichier doivent être liés cryptographiquement au contenu, y compris pour un fichier vide.
- **Nonce unique pour chaque clé AES-GCM** : construction déterministe définie par le format, à partir du contexte et d'un compteur ; aucun recyclage ni débordement. Séparer les domaines pour les données, la terminaison et les autres opérations.
- **Ordre et appartenance** : les données associées authentifiées doivent lier chaque bloc à son fichier, à son index, à son type et à sa longueur. Le lecteur impose la séquence attendue et refuse suppression, duplication, permutation ou collage entre archives.
- **Fin obligatoire** : authentifier le nombre de blocs et la longueur totale, vérifier leur cohérence et rejeter les octets supplémentaires. Sans terminaison authentifiée, un préfixe valide pourrait être accepté comme fichier complet.
- **Bornes cryptographiques** : définir un budget de données et d'invocations par clé et une politique de changement de clé si nécessaire. Un compteur très large ne constitue pas une preuve de sécurité.
- **Entrées hostiles** : contrôler longueurs, paramètres, compteurs et ressources avant d'allouer ou de lancer Argon2 ; ne jamais remettre un bloc dont le tag est invalide.

Un bloc vérifié peut être remis au consommateur avant la fin, mais cela prouve seulement l'authenticité de ce bloc dans son contexte. **Le fichier complet n'est accepté qu'après validation de la terminaison.** Une erreur tardive doit invalider l'opération, même si des blocs antérieurs étaient corrects.

### API et comportement applicatif

Prévoir une API recevant une source et une destination de flux, avec progression, annulation par `AbortSignal` et propagation des erreurs de lecture/écriture. Par exemple, des noms `encryptStreamV2` / `decryptStreamV2` seraient cohérents ; leur signature reste à concevoir. La promesse d'opération ne doit réussir qu'après validation finale et finalisation de l'écriture.

Des adaptateurs Node peuvent gérer les fichiers ; des adaptateurs navigateur peuvent gérer `File` et les destinations disponibles. Une API de commodité `encryptBytesV2` resterait possible pour les petits contenus, mais conserverait les limites des buffers complets.

Pour une destination fichier, écrire dans une sortie temporaire puis la finaliser après succès, avec des permissions appropriées. En cas d'échec ou d'annulation, interrompre les flux et nettoyer au mieux les sorties partielles. Une destination réseau ou un consommateur ayant déjà utilisé des blocs ne permet pas de les « reprendre » : son contrat doit prévoir l'état incomplet et la confirmation finale.

## 4. Limites qui resteront

### Cryptographie et compteurs

AES-GCM limite la longueur du clair d'une invocation à **2³⁹ − 256 bits**, soit **2³⁶ − 32 octets : 64 Gio moins 32 octets**. C'est une borne algorithmique par message, pas une taille prise en charge par la v1. Les moteurs et la RAM peuvent imposer une limite inférieure. Voir [NIST SP 800-38D, §5.2.1.1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

Le découpage en blocs contourne cette borne par message pour la taille totale du fichier ; il ne supprime pas les exigences d'unicité des nonces et les budgets de sécurité cumulés par clé. Ces contraintes doivent être examinées lors de la revue cryptographique.

Exemple arithmétique uniquement : un compteur de 32 bits représente 2³² valeurs ; à 4 Mio par bloc, cela correspond à 16 Pio avant réservations. **Ce chiffre n'est pas un maximum sûr recommandé** : certaines valeurs peuvent être réservées et le budget par clé peut imposer une borne beaucoup plus basse. Choisir les compteurs et le renouvellement de clé après cette analyse.

Pour les tailles et offsets cumulés, utiliser des entiers 64 bits dans le format et `bigint` lorsque nécessaire dans le code. Un `number` JavaScript ne représente exactement tous les entiers que jusqu'à 2⁵³ − 1 ; ne pas effectuer de conversion silencieuse au-delà. Les adaptateurs de fichiers peuvent imposer leurs propres bornes.

### Disque et stockage

La sortie occupe approximativement la taille de l'entrée, plus les tags et métadonnées. Un tag de 16 octets par bloc de 4 Mio ajoute environ **0,00038 %** ; pour 10 Gio, les tags de données seuls occupent 40 Kio. Le format complet aura un surcoût supplémentaire à définir.

Il faut disposer d'espace pour la sortie et, selon la stratégie, une copie temporaire supplémentaire. Le streaming réduit la RAM, pas le stockage nécessaire. La taille maximale de fichier dépend aussi du système de fichiers et du service de destination ; les quotas ou limites d'upload restent indépendants du chiffrement.

Dans le navigateur, distinguer le fichier local choisi par l'utilisateur et l'OPFS, stockage privé de l'origine. Les quotas de stockage web concernent ce dernier ; un disque plein peut faire échouer les deux. Voir [le standard File System, écriture et quotas](https://fs.spec.whatwg.org/#api-filesystemwritablefilestream).

### Navigateurs et mobiles

La lecture progressive ne suffit pas : **la sortie doit également être progressive**. Sinon, le résultat finit de nouveau par s'accumuler en mémoire.

| Environnement | Stratégie proposée | Limites restantes |
| --- | --- | --- |
| Node.js 24+ / CLI | Flux de fichiers, sortie temporaire puis finalisation | Disque, droits, durée et ressources de la machine. |
| Chrome / Edge avec accès aux fichiers disponible | `File.stream()` ou lectures bornées, Worker et destination writable choisie par l'utilisateur | Contexte sécurisé, interaction/permissions utilisateur et capacité détectée à l'exécution. |
| Firefox / Safari | Étudier OPFS et le parcours réel d'export, ou une destination réseau explicite | Le sélecteur de sauvegarde direct n'est pas une capacité portable ; l'export peut recréer un problème de mémoire. |
| Appareils mobiles | Blocs et concurrence adaptés après mesures | Mémoire Argon2, stockage libre, chauffe, batterie, suspension de l'application. |

La documentation Chrome distingue l'accès direct aux fichiers et l'OPFS ; leur support ne doit pas être confondu. Voir [File System Access et OPFS](https://developer.chrome.com/docs/capabilities/web-apis/file-system-access). Il faut détecter les fonctionnalités et qualifier les versions effectivement supportées, plutôt que promettre plusieurs Go dans tous les navigateurs.

Une destination réseau reste une décision de l'intégrateur et de l'utilisateur. Elle ne doit pas être introduite comme solution implicite dans une bibliothèque de chiffrement local.

### Temps, interruption et reprise

La durée reste proportionnelle au volume. À un débit effectif hypothétique de 100 Mio/s, 10 Gio prennent environ 102 secondes de traitement, auxquels s'ajoutent le démarrage du KDF et les éventuels temps d'attente. Ce calcul n'est pas un benchmark ClearCrypt.

Progression et annulation sont réalistes dès la première v2. **La reprise après interruption n'est pas automatique avec le streaming.** Elle exige une source stable, des points de reprise authentifiés et un état empêchant toute réutilisation clé/nonce, notamment si le fichier source change. Recommencer avec une nouvelle clé et un nouveau contexte est la solution initiale la plus simple ; réserver la reprise à une évolution séparée.

Les fichiers volumineux peuvent changer pendant leur lecture : les adaptateurs doivent documenter cette situation et, si nécessaire, vérifier leur stabilité ou utiliser un instantané.

### Confidentialité et sorties incomplètes

Le plaintext et les clés existent toujours temporairement en mémoire. L'effacement JavaScript reste au mieux volontaire et partiel, comme décrit dans [la documentation mémoire v1](memory-v1.md). Un fichier temporaire déchiffré contient des données sensibles ; sa suppression ne garantit pas leur effacement physique sur disque.

Le format révèle au minimum une taille approximative et des informations d'en-tête. Masquer la taille nécessiterait du padding et du stockage supplémentaire. Une intégrité valide n'assure pas la fraîcheur : rejouer une ancienne archive complète et valide nécessite une protection externe si ce risque compte pour l'application.

## 5. Compatibilité et périmètre conseillé

La version du package npm et celle du format d'archive sont deux décisions distinctes. Un package majeur v2 peut conserver `encryptBytesV1` et `decryptBytesV1`, puis ajouter des API v2 explicites. Un lecteur v1 doit refuser `CFENC002` ; il ne peut pas interpréter les nouveaux blocs.

Préserver les archives existantes, leurs vecteurs et leur spécification. Ajouter éventuellement une détection de format, avec rejet explicite des versions inconnues. Ne pas convertir les fichiers silencieusement. La conversion v1 vers v2 passe par un déchiffrement puis un rechiffrement ; avec le lecteur v1 actuel, elle reste soumise aux limites mémoire v1. Un pont Node en streaming pourrait être une évolution distincte.

Périmètre initial recommandé : **flux séquentiels, format v2 authentifié par blocs, fichiers vides, annulation, progression et finalisation sûre des sorties**. Reporter la reprise après crash, l'accès aléatoire et la modification en place ; chacun ajoute des règles cryptographiques et de stockage.

## 6. Travaux nécessaires avant une promesse multi-Go

1. **Figer une spécification binaire v2** : framing, tailles maximales, AAD, nonces, fin de flux, budget par clé, limites globales et erreurs. Comparer AES-GCM par blocs à `secretstream`, puis faire relire le choix et la construction.
2. **Implémenter le cœur de flux et les adaptateurs** : lecture partielle, contre-pression, annulation et erreurs ; commencer avec une concurrence bornée, idéalement séquentielle.
3. **Adapter la CLI et les intégrations web** : supprimer la lecture intégrale, choisir une vraie destination de flux et empêcher qu'une sortie partielle apparaisse comme réussie.
4. **Valider sécurité et interopérabilité** : vecteurs indépendants ; échanges Node/navigateurs ; mot de passe incorrect ; altération, permutation, duplication, collage, troncature, absence de fin, données après la fin et champs hostiles.
5. **Mesurer les ressources** : round trips de 1, 4 et 10 Gio, dont des cas dépassant 4 Gio ; générer/lire les données en flux et comparer des empreintes, sans charger les fichiers en RAM pour le test. Vérifier que le pic mémoire reste borné lorsque la taille augmente.
6. **Tester les défaillances réelles** : disque plein, quota OPFS, destination lente, panne d'écriture, annulation, crash et nettoyage ; qualifier desktop et mobile séparément.
7. **Publier une matrice de support mesurée** : appareils, runtimes, destinations, tailles testées, temps et pics mémoire. Annoncer les capacités validées et les plafonds de sécurité du format.

Le principal chantier est donc **un format et une API de streaming authentifié**, puis leur intégration jusqu'à la destination. Supprimer un plafond d'interface seul ne permettra pas de garantir le chiffrement de plusieurs Go.

## 7. Concrètement, quels fichiers et comportements changer ?

La stratégie est d'ajouter une implémentation `src/v2/` à côté de `src/v1/`. Les archives `CFENC001` et les fonctions publiques v1 conservent leur comportement. La v2 écrit des archives `CFENC002` ; les anciens lecteurs ne pourront pas les ouvrir et devront être mis à jour.

### Dans le package ClearCrypt

| Zone | Changement concret proposé |
| --- | --- |
| Nouveau `docs/format-v2.md` | Spécification normative de l'en-tête, des blocs, des nonces, des budgets par clé et de la terminaison. À approuver techniquement avant de stabiliser le format. |
| Nouveau `src/v2/spec/` | Constantes, identifiants, structures et bornes du format v2. |
| Nouveau `src/v2/reader.ts` | Parseur incrémental : conserver seulement un en-tête ou un bloc incomplet, vérifier les tailles avant allocation et reconnaître la fin obligatoire. |
| Nouveau `src/v2/writer.ts` | Émettre l'en-tête, les blocs puis la terminaison vers une destination ; aucune concaténation de l'archive entière. |
| Nouveau `src/v2/format.ts` | Authentification des blocs et de leur ordre, gestion des compteurs et clés, vérification des totaux et rejet des données supplémentaires. |
| Nouveau `src/v2/api.ts` | API de source/destination, progression, annulation, erreurs et résultat final d'opération. |
| `src/index.ts` | Ajouter les exports v2 en conservant les exports v1. |
| Primitives AES-GCM, Argon2, mots de passe et enveloppe de clé | Réutiliser les primitives fiables après vérification de leur adéquation ; séparer les helpers communs si nécessaire. Le contexte authentifié de l'enveloppe v2 doit être défini par la nouvelle spécification. |
| Builds Node et navigateur | Vérifier les exports et l'adaptation Argon2. Le build navigateur actuel redirige `./argon2/runtime` : préserver ce mécanisme ou l'adapter si les helpers sont déplacés. Garder les imports de fichiers Node hors du bundle navigateur. |
| `scripts/cc-file.mjs` | Ajouter un chemin v2 utilisant des flux de fichiers, avec gestion d'une sortie temporaire et conservation de la lecture v1. |
| Tests, benchmarks, CI et documentation | Ajouter vecteurs v2, vérifications de flux et d'intégrité, tests multi-Go et mémoire ; maintenir les tests v1. Exécuter les essais lourds dans une campagne adaptée plutôt qu'à chaque petit changement. |

La cryptographie par blocs peut employer les appels WebCrypto existants sur de petits buffers. Ce sont le conteneur et l'orchestration qui changent le plus. Il faudra définir explicitement le type d'erreur et la sémantique d'annulation sans modifier les résultats attendus par les utilisateurs de la v1.

### Dans Tegelis, dépôt applicatif séparé

1. **Lecture** : remplacer la lecture intégrale du fichier, si elle est utilisée, par `File.stream()` ou des lectures bornées avec `slice()`. Le code du site devra être inspecté pour identifier précisément le chemin actuel.
2. **Worker** : traiter les blocs et transmettre les données avec une file bornée. Éviter un message contenant le fichier entier ou une copie de chaque bloc conservée jusqu'à la fin.
3. **Sauvegarde** : choisir la destination avant le traitement, puis écrire les blocs progressivement. Une accumulation dans un `Blob` final annulerait le bénéfice mémoire du streaming.
4. **Choix du format** : utiliser v2 pour le nouveau parcours streaming. Au déchiffrement, lire le préfixe pour aiguiller vers le lecteur v1 ou v2 ; conserver le parcours v1 à buffers pour les anciennes archives.
5. **Interface** : progression, annulation, erreurs disque/permissions et confirmation finale. Afficher le succès seulement après validation et fermeture de la sortie.
6. **Plafond** : conserver 100 Mo pour le parcours v1 actuellement éprouvé ; proposer un plafond supérieur pour le parcours v2 uniquement sur les configurations qualifiées. Une limite v1 de déchiffrement doit tenir compte du surcoût de l'archive, afin d'accepter une archive issue d'un clair à la taille maximale.
7. **Navigateurs sans destination locale progressive validée** : maintenir le parcours actuel, ou développer puis tester un autre parcours de sauvegarde. Le support du chiffrement v2 seul ne garantit pas celui de l'export multi-Go.

L'ordre de livraison conseillé est : **spécification → cœur v2 et vecteurs → CLI de référence → parcours web de sauvegarde progressive → qualification multi-Go → élargissement du support navigateur**.

## 8. Estimation des performances

Il n'existe pas encore de benchmark v2. Le retour Tegelis à 100 Mo ne comporte pas de durée ni de configuration matérielle ; il ne permet donc pas de déduire un débit. Les chiffres ci-dessous sont des **scénarios de dimensionnement**, pas des mesures ni une garantie sur un appareil donné.

### Durée de chiffrement ou de déchiffrement

Pour une opération : `durée ≈ coût initial Argon2 + volume / débit effectif + finalisation`.

Le débit effectif inclut la lecture, les copies, la cryptographie par blocs et l'écriture. Avec un pipeline séquentiel, leurs durées peuvent s'additionner ; avec des étapes recouvrantes, la plus lente tend à dominer. Il ne faut donc pas prendre un benchmark AES seul comme débit de l'application.

| Volume | Scénario 25 Mio/s | Scénario 100 Mio/s | Scénario 250 Mio/s |
| --- | ---: | ---: | ---: |
| 100 Mo | 3,8 s | 1,0 s | 0,4 s |
| 1 Gio | 41 s | 10 s | 4 s |
| 4 Gio | 2 min 44 s | 41 s | 16 s |
| 10 Gio | 6 min 50 s | 1 min 42 s | 41 s |

Ces durées excluent le coût initial d'Argon2 et la finalisation. Elles valent pour **une seule opération** ; chiffrer puis déchiffrer nécessite deux opérations, avec des débits potentiellement différents. Les trois colonnes illustrent la sensibilité au débit, sans attribuer un débit à un navigateur ou à un type d'appareil.

Avec des blocs de 4 Mio, un fichier de 10 Gio représente 2 560 blocs de données. Le surcoût des appels par bloc, de leur authentification et des messages Worker devra être mesuré. La v2 n'est pas nécessairement plus rapide pour un petit fichier : son gain principal est la capacité à traiter de gros volumes avec une mémoire stable. Éviter les allocations complètes et les grosses concaténations peut toutefois améliorer le comportement sur les grands fichiers.

### Mémoire attendue

Objectif initial : blocs de 4 Mio, traitement séquentiel, files bornées et environ **3 à 8 buffers de bloc simultanés**, soit **12 à 32 Mio de buffers de traitement visibles**. C'est un budget de conception à vérifier, pas une borne du runtime.

En ajoutant le coût nominal Argon2, cela donne un budget indicatif de **76 à 96 Mio avec le profil 64 Mio**, ou **140 à 160 Mio avec le profil 128 Mio**, avant mémoire de base de la page/du processus, état WASM, copies internes et buffers de stockage. Les phases ne sont pas nécessairement simultanées, mais la mémoire WASM peut rester allouée après le KDF. Mesurer le pic réel et la mémoire retenue après opération.

Ce budget devrait rester du même ordre pour 1, 4 ou 10 Gio si toute la chaîne respecte la contre-pression. La mémoire totale de Tegelis sera supérieure et dépendra de son intégration. Plusieurs opérations en parallèle multiplient les besoins ; commencer par une seule opération à la fois.

### Comment obtenir une estimation fiable pour Tegelis

Mesurer séparément le démarrage d'Argon2, puis les débits de lecture, de traitement cryptographique et de sauvegarde, et enfin le temps complet. Comparer des blocs de 1, 4 et 8 Mio sur les mêmes appareils, avec la même destination et le même profil KDF. Effectuer plusieurs passages et distinguer le chargement initial WASM des passages suivants.

Inclure chiffrement et déchiffrement, 100 Mo comme référence actuelle, puis 1, 4 et 10 Gio ; relever le pic mémoire et la réactivité de l'interface. La première cible à décider n'est pas « infini », mais un couple mesuré : **taille qualifiée et débit soutenu sur les environnements supportés**.

## Références du dépôt

- [API publique v1](../src/v1/api.ts), [implémentation AES-GCM](../src/v1/aead.ts).
- [Format et sérialisation v1](../src/v1/format.ts), [assemblage des buffers](../src/v1/writer.ts).
- [Politique de ressources Argon2](../src/v1/resource-policy.ts), [CLI actuelle](../scripts/cc-file.mjs).
- [Spécification CFENC001](format-v1.md), [mémoire v1](memory-v1.md), [profils Argon2](argon2-profiles-v1.md).
