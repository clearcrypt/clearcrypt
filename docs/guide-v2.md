# Guide pratique ClearCrypt V2

`CFENC002` traite les archives par enregistrements authentifiés afin que la
mémoire utilisée ne dépende pas de la taille totale du fichier. Le format V1
reste pris en charge sans changement.

## Choisir V1 ou V2

| Besoin | API | Format | Mémoire |
| --- | --- | --- | --- |
| petit contenu déjà en mémoire | `encryptBytesV1` / `decryptBytesV1` | `CFENC001` | proportionnelle à la taille totale |
| fichier ou flux, notamment plusieurs Gio | `encryptStreamV2` / `decryptStreamV2` | `CFENC002` | bornée par le KDF, la taille de bloc et l'adaptateur |
| fichier Node.js avec remplacement atomique | `encryptFileV2` / `decryptFileV2` depuis `clearcrypt/node` | `CFENC002` | bornée |

V2 utilise des blocs de 4 Mio par défaut. Le chiffrement accepte une puissance
de deux comprise entre 64 Kio et 16 Mio. Un bloc plus grand réduit légèrement
le framing mais augmente la mémoire vivante et le délai d'annulation. Les
mesures actuelles ne justifient pas un bloc de 100 Mio.

## API de flux

```ts
import { encryptStreamV2 } from "clearcrypt";

const controller = new AbortController();
const result = await encryptStreamV2(source, destination, password, {
  chunkSize: 4 * 1024 * 1024,
  signal: controller.signal,
  onProgress({ phase, inputBytes, outputBytes, records }) {
    console.log(phase, inputBytes, outputBytes, records);
  },
});

console.log(result.format); // CFENC002
```

`source` est un `ReadableStream<Uint8Array>` et `destination` un
`WritableStream<Uint8Array>`. `decryptStreamV2` possède la même forme et peut
recevoir une `resourcePolicy` pour borner les paramètres Argon2id acceptés.
Les compteurs utilisent `bigint`.

La contre-pression de `WritableStream` empêche le cœur d'accumuler une file non
bornée. L'adaptateur doit conserver cette propriété : convertir toute la source
ou toute la sortie en `Blob`, `ArrayBuffer` ou tableau annule le bénéfice du
streaming.

## Fichiers Node.js et CLI

```ts
import { decryptFileV2, encryptFileV2 } from "clearcrypt/node";

await encryptFileV2("archive.tar", "archive.tar.cc2", password);
await decryptFileV2("archive.tar.cc2", "archive-restauree.tar", password);
```

L'adaptateur écrit dans un fichier temporaire voisin puis remplace la
destination lorsque l'opération complète a réussi. La CLI fournit le même
comportement :

```sh
node scripts/cc-file.mjs encrypt-v2 archive.tar archive.tar.cc2
node scripts/cc-file.mjs decrypt-v2 archive.tar.cc2 archive-restauree.tar
```

## Navigateur et Web Worker

Le chiffrement doit tourner dans un Web Worker pour maintenir l'interface
réactive. Créer la source et la destination dans le Worker est préférable. Si
des blocs transitent depuis la page, utiliser des `ArrayBuffer` transférables,
une file fixe et un acquittement avant le bloc suivant.

Une intégration peut lire `File.stream()`. Pour les grands fichiers, elle doit
aussi disposer d'une destination réellement progressive. Une API qui exige un
`Blob` complet limite la taille utilisable même si ClearCrypt reste borné.

Les capacités nécessaires sont Web Crypto, WebAssembly, les WHATWG Streams,
les Workers modules et `AbortController`. La qualification automatisée couvre
Chromium, Firefox et WebKit ; les limites mesurées sont publiées dans
[qualification-v2.md](qualification-v2.md).

## Succès, erreur et annulation

Chaque bloc déchiffré est authentifié avant son écriture, mais seule la
validation de l'enregistrement `FINAL` prouve que l'archive entière est
complète. Une sortie partielle ne doit donc jamais être publiée ou ouverte
comme résultat valide.

La promesse ne réussit qu'après validation de `FINAL` et fermeture de la
destination. En cas d'erreur ou d'annulation, ClearCrypt annule la source et
abandonne la destination lorsque les Streams le permettent. Des octets peuvent
rester physiquement présents : utiliser une destination temporaire ou
transactionnelle. L'annulation est coopérative ; une opération Argon2id ou Web
Crypto déjà lancée peut finir avant que le signal soit observé.

## Détection et compatibilité

Les huit premiers octets ASCII suffisent pour choisir le lecteur :

```ts
type ClearcryptFormat = "CFENC001" | "CFENC002";

function detectClearcryptFormat(prefix: Uint8Array): ClearcryptFormat {
  if (prefix.byteLength < 8) throw new Error("Archive ClearCrypt tronquée");
  const magic = new TextDecoder("ascii", { fatal: true }).decode(prefix.subarray(0, 8));
  if (magic === "CFENC001" || magic === "CFENC002") return magic;
  throw new Error("Format ClearCrypt inconnu");
}
```

Cette détection n'authentifie pas l'archive. Une application doit conserver les
huit octets dans l'entrée transmise au lecteur. Il n'existe pas de déchiffrement
automatique commun, car V1 exige l'archive complète en mémoire tandis que V2
consomme un flux.

- `encryptBytesV1` continue toujours de produire `CFENC001` ;
- `encryptStreamV2` produit toujours `CFENC002` ;
- les lecteurs rejettent les versions et algorithmes inconnus ;
- les archives V1 existantes restent lisibles par `decryptBytesV1`.

Convertir V1 vers V2 exige de déchiffrer le contenu avec V1 puis de le chiffrer
à nouveau avec V2. Comme l'API V1 est en mémoire, cette conversion n'est pas
bornée pour une grosse archive V1. Le clair intermédiaire doit être protégé et
supprimé après réussite.

## Limites

Le protocole accepte au plus 1 Pio de clair et change de clé de segment tous
les 1 Gio. Cette borne cryptographique n'est pas une promesse pratique. Le
temps, l'espace libre, les erreurs du support, les quotas du navigateur, la
mémoire du KDF, la mise en veille et les contraintes thermiques restent les
limites réelles.

Lors de la campagne Node.js de référence, le pic RSS était de 214,00 Mio à
220,41 Mio pour des archives réelles de 1 à 100 Gio. Ce chiffre dépend du
runtime, du KDF et de l'adaptateur ; il ne constitue pas une allocation garantie
sur chaque appareil.

La première implémentation est séquentielle. Elle ne fournit ni reprise après
interruption, ni accès aléatoire, ni compression, ni padding de taille, ni
stockage ou transfert réseau. Un mot de passe perdu ne peut pas être récupéré.
