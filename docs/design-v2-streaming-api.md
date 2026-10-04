# ClearCrypt v2 : périmètre et contrat de l'API de streaming

Date : 4 octobre 2026. Statut : décision de conception pour V2-001.

Cette note fixe le périmètre de la première version streaming de ClearCrypt. Elle définit le contrat attendu de l'API avant la spécification binaire de `CFENC002`. Les détails cryptographiques et les octets du format seront définis par V2-002 et V2-003.

## Décision

ClearCrypt v2 exposera deux opérations séquentielles fondées sur les WHATWG Streams, disponibles dans les navigateurs modernes et dans Node.js 24 :

```ts
export type V2Progress = {
  phase: "kdf" | "processing" | "finalizing";
  inputBytes: bigint;
  outputBytes: bigint;
  records: bigint;
};

export type V2OperationResult = {
  format: "CFENC002";
  inputBytes: bigint;
  outputBytes: bigint;
  records: bigint;
};

export type V2StreamOptions = {
  signal?: AbortSignal;
  onProgress?: (progress: V2Progress) => void;
};

export async function encryptStreamV2(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  password: Uint8Array | string,
  options?: V2EncryptOptions
): Promise<V2OperationResult>;

export async function decryptStreamV2(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  password: Uint8Array | string,
  options?: V2DecryptOptions
): Promise<V2OperationResult>;
```

`V2EncryptOptions` et `V2DecryptOptions` étendront les options communes ci-dessus. Les paramètres KDF, la politique de ressources et l'éventuelle taille de bloc configurable seront précisés après stabilisation du format.

Les types publics utiliseront `bigint` pour les compteurs d'octets et d'enregistrements. Un fichier de 100 Go reste représentable par un `number`, mais l'API ne doit pas créer une limite implicite à 2⁵³ − 1 octets.

## Pourquoi les WHATWG Streams

- `ReadableStream` et `WritableStream` fournissent une contre-pression standard ;
- ils existent nativement dans les navigateurs ciblés ;
- Node.js 24 fournit les Web Streams et des adaptateurs pour ses flux de fichiers ;
- le cœur n'a pas besoin de connaître les fichiers, les réseaux ou le stockage ;
- une source et une destination instrumentées peuvent tester plusieurs Go sans les conserver en mémoire.

Les adaptateurs de fichiers Node, les Web Workers et les intégrations applicatives seront construits au-dessus de ce contrat. Ils ne feront pas partie de la logique cryptographique du format.

## Garanties de la première v2

Pour une archive complète acceptée, ClearCrypt garantit :

- la confidentialité du contenu sous les hypothèses des primitives retenues et d'un mot de passe adéquat ;
- l'authentification indépendante de chaque enregistrement avant remise de son plaintext à la destination ;
- l'authentification de l'en-tête et des paramètres qui doivent être liés au contenu ;
- la détection d'un bloc altéré, supprimé, dupliqué, réordonné ou provenant d'une autre archive ;
- la détection d'une archive tronquée ou contenant des données après sa terminaison ;
- la validation authentifiée du nombre de blocs et de la longueur totale ;
- une mémoire de travail bornée par les paramètres du format et indépendante de la taille totale ;
- l'application de la politique de ressources avant le lancement d'Argon2id pendant le déchiffrement.

La promesse retournée ne réussit qu'après authentification de la terminaison et fermeture réussie de la destination.

## Modèle de menace

Le lecteur considère toute archive comme hostile. Il valide les identifiants, tailles, compteurs et paramètres de ressources avant une allocation coûteuse ou une opération cryptographique correspondante.

Le modèle couvre :

- un mot de passe incorrect ;
- une modification volontaire ou accidentelle des octets ;
- la suppression, duplication ou permutation d'enregistrements ;
- le collage de données provenant d'une autre archive ;
- la troncature à n'importe quel emplacement ;
- les longueurs, compteurs et paramètres conçus pour provoquer un dépassement ou une allocation excessive ;
- une erreur ou une interruption de la source ou de la destination.

Le modèle ne protège pas contre :

- un appareil, navigateur ou processus déjà compromis ;
- la capture du mot de passe ou du plaintext par l'application appelante ;
- l'analyse de trafic ou la révélation de la taille approximative de l'archive ;
- le rejeu d'une ancienne archive complète et valide ;
- la perte ou la faiblesse du mot de passe ;
- les copies conservées par le runtime, le système d'exploitation, le swap ou les supports physiques.

## Contre-pression et mémoire

Le pipeline ne lit un nouveau volume de données que lorsqu'il dispose d'une capacité bornée pour le traiter et que la destination progresse. Il ne conserve jamais une liste non bornée de lectures, de promesses, de blocs chiffrés ou de blocs en attente d'écriture.

La première implémentation traite les enregistrements séquentiellement. Elle peut conserver quelques buffers de travail, mais leur nombre et leur taille doivent être bornés. Une destination lente ralentit naturellement la lecture de la source.

Le multithreading et le traitement parallèle de plusieurs blocs sont reportés. Ils ne seront ajoutés qu'après mesure d'un bénéfice réel et devront conserver une file bornée, l'ordre du format et l'unicité des nonces.

## Cycle de vie de l'opération

### Succès

1. L'opération acquiert un reader sur la source et un writer sur la destination.
2. Elle initialise le KDF et l'enveloppe de clé.
3. Elle lit, traite et écrit les enregistrements en respectant la contre-pression.
4. Elle écrit ou valide la terminaison authentifiée.
5. Elle ferme la destination.
6. Elle libère les verrous et retourne `V2OperationResult`.

Le résultat compte les octets réellement consommés et écrits par ClearCrypt. Les adaptateurs peuvent utiliser ces valeurs pour vérifier leur propre progression.

### Erreur

Lorsqu'une lecture, une écriture, le KDF, le parseur ou l'authentification échoue :

- l'opération rejette sa promesse avec une erreur publique ClearCrypt appropriée ;
- elle annule la source si elle la contrôle encore ;
- elle abort la destination si elle la contrôle encore ;
- elle cesse de lire et d'écrire dès que possible ;
- elle efface au mieux les buffers secrets temporaires appartenant au package ;
- elle libère les verrous dans un bloc `finally`.

Une destination déjà partiellement écrite peut conserver physiquement des octets. ClearCrypt ne promet pas de transaction ni de suppression, car ces capacités dépendent de la destination. L'appelant doit écrire dans une destination temporaire ou transactionnelle lorsqu'il a besoin d'une publication atomique.

### Annulation

Un `AbortSignal` déjà annulé empêche le démarrage du KDF. Une annulation ultérieure suit le même chemin qu'une erreur : arrêt au prochain point sûr, annulation de la source, abandon de la destination et rejet de la promesse.

L'annulation est coopérative. ClearCrypt ne peut pas garantir l'arrêt instantané d'un appel WebCrypto ou Argon2 déjà en cours si le runtime ne fournit pas lui-même cette capacité.

### Callback de progression

La progression est émise lors des transitions de phase et après l'écriture réussie d'un enregistrement, pas pour chaque petit morceau fourni par la source. Cela évite une fréquence non bornée et indique uniquement du travail effectivement avancé.

Le callback est synchrone et ne participe pas à la contre-pression. S'il lève une exception, l'opération est considérée comme échouée et applique le cycle d'erreur. Une application qui effectue un travail asynchrone ou coûteux dans ce callback doit gérer sa propre file bornée.

La taille totale est volontairement absente du contrat de base : une source générique peut être de longueur inconnue. Une application qui connaît la taille peut calculer son pourcentage à partir de `inputBytes`.

## Déchiffrement progressif et validation finale

Un bloc n'est écrit vers la destination qu'après validation de son tag. Cela établit l'authenticité du bloc et de sa position attendue.

La présence de blocs valides ne prouve pas que l'archive est complète. Seule la terminaison authentifiée valide l'ensemble. L'appelant ne doit donc pas publier, ouvrir ou traiter une sortie partielle comme un fichier complet avant la résolution de la promesse.

Cette règle est particulièrement importante lorsqu'une archive est tronquée juste après un bloc valide.

## Compatibilité v1

Les API suivantes restent inchangées :

```ts
encryptBytesV1(...)
decryptBytesV1(...)
```

`CFENC001` reste un format à buffers complets. Aucun faux streaming ne sera ajouté à sa spécification.

L'écriture d'une nouvelle archive v2 se fait explicitement avec `encryptStreamV2`. Une fonction de détection pourra lire le magic pour distinguer `CFENC001` et `CFENC002`, mais elle ne choisira pas silencieusement un format d'écriture.

Une API de déchiffrement automatique est reportée jusqu'à la définition des adaptateurs : la v1 exige aujourd'hui l'archive complète alors que la v2 accepte un flux. La détection du magic ne doit pas faire croire que ces deux chemins ont le même comportement mémoire.

## Hors périmètre de la première version

- multithreading et chiffrement parallèle des blocs ;
- reprise après crash, fermeture du navigateur ou interruption du processus ;
- reprise d'upload ou de téléchargement ;
- accès aléatoire à un bloc ;
- modification d'une archive en place ;
- compression ;
- masquage de la taille par padding ;
- stockage, transport réseau ou intégration à un fournisseur cloud ;
- métadonnées applicatives comme le nom ou le chemin du fichier ;
- migration automatique d'une archive v1 vers v2 ;
- changement silencieux du format utilisé par les API v1.

La reprise mentionnée dans d'anciens documents de cadrage reste un objectif potentiel, mais elle nécessite un protocole supplémentaire pour les points de reprise et la prévention de toute réutilisation clé/nonce. Elle ne fait pas partie du premier format streaming stabilisé.

## Conséquences pour les tickets suivants

- V2-002 doit spécifier un framing séquentiel et une terminaison obligatoire.
- V2-003 doit calculer les budgets cryptographiques pour la taille maximale normative.
- V2-005 et V2-006 doivent travailler avec des morceaux arbitraires et une contre-pression réelle.
- V2-009 et V2-010 doivent implémenter les cycles succès, erreur et annulation définis ici.
- V2-011 doit confirmer ces signatures à partir de l'expérience d'implémentation sans en affaiblir les garanties.
- V2-012 et V2-013 doivent fournir les adaptateurs de plateforme sans introduire de buffers complets.

