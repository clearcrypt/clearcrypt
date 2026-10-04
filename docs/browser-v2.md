# ClearCrypt v2 dans un navigateur et un Web Worker

Date : 4 octobre 2026. Statut : parcours de référence validé pour V2-013.

## Architecture recommandée

Le chiffrement et le déchiffrement v2 doivent être exécutés dans un Web Worker.
Le Worker construit ou reçoit une source `ReadableStream<Uint8Array>`, une
destination `WritableStream<Uint8Array>`, puis appelle `encryptStreamV2` ou
`decryptStreamV2`. La page principale conserve uniquement l'interface, la
progression et la commande d'annulation.

```js
const controller = new AbortController();

await encryptStreamV2(source, destination, password, {
  signal: controller.signal,
  onProgress(progress) {
    self.postMessage({
      type: "progress",
      inputBytes: progress.inputBytes.toString(),
      outputBytes: progress.outputBytes.toString(),
      records: progress.records.toString(),
    });
  },
});
```

La source et la destination doivent être créées dans le Worker lorsque la
plateforme le permet. Si l'application doit faire transiter des morceaux entre
la page et le Worker, elle doit utiliser une file de taille fixe, transférer les
`ArrayBuffer` et attendre un acquittement avant d'envoyer les suivants. Envoyer
le fichier ou l'archive complète dans un message supprime le bénéfice mémoire du
streaming.

## Sources et destinations

ClearCrypt ne choisit pas le stockage. Une intégration peut notamment fournir :

- une source issue de `File.stream()` ou d'un lecteur applicatif borné ;
- une destination progressive vers un fichier, un stockage local, un upload ou
  une destination instrumentée ;
- une destination temporaire ou transactionnelle lorsque le résultat ne doit
  être publié qu'après validation complète.

Construire un `Blob` contenant toute l'archive reste possible pour un petit
fichier, mais réintroduit une allocation proportionnelle à sa taille. Ce n'est
pas le parcours prévu pour les archives volumineuses. Le cœur v2 n'exige aucun
`Blob` complet.

Pendant le déchiffrement, chaque bloc est authentifié avant son écriture. La
sortie entière ne doit toutefois être présentée comme valide qu'après la
résolution de `decryptStreamV2`, car l'enregistrement `FINAL` authentifie la
complétude de l'archive.

## Capacités requises

L'environnement navigateur doit fournir :

- un contexte autorisant Web Crypto ;
- `Worker` avec modules JavaScript ;
- WebAssembly pour Argon2id ;
- `ReadableStream` et `WritableStream` ;
- `AbortController` et `AbortSignal` ;
- assez de mémoire pour le profil Argon2id choisi, les buffers cryptographiques
  et les données vivantes de l'application.

La capacité de sauvegarder progressivement vers un fichier dépend de
l'environnement hôte et de l'adaptateur de l'application. Elle doit être
détectée au démarrage du parcours. ClearCrypt peut chiffrer vers tout
`WritableStream`, mais il ne peut pas ajouter une écriture progressive à une API
de destination qui exige elle-même un `Blob` complet.

## Annulation et fermeture

La page envoie une commande d'annulation au Worker. Le Worker appelle
`AbortController.abort()`, attend le rejet `ABORTED`, laisse ClearCrypt annuler
la source et abort la destination, puis se ferme. L'annulation est coopérative :
un appel Argon2id ou Web Crypto déjà en cours peut terminer avant que le signal
soit observé.

Une application doit considérer toute destination partielle comme invalide.
Lorsque l'adaptateur le permet, elle doit supprimer ou abandonner cette
destination après une erreur ou une annulation.

## Validation automatisée

La suite Playwright exécute le même bundle dans Chromium, Firefox et WebKit. Elle
vérifie :

- un aller-retour v2 complet dans un Worker ;
- l'activité continue de la boucle d'événements de la page ;
- une source et une destination limitées à des morceaux de 64 Kio ;
- une contre-pression qui n'autorise qu'une écriture active ;
- la stabilité de ces bornes entre des entrées simulées de 1 et 8 Mio ;
- l'absence de transfert de l'archive complète vers la page ;
- l'annulation coopérative de la source et de la destination ;
- la fermeture du Worker après succès ou annulation.

Cette validation démontre le comportement borné du pipeline et de l'adaptateur
de test. Les mesures de mémoire et de débit sur de grands fichiers et appareils
réels relèvent de V2-016 et V2-017.
