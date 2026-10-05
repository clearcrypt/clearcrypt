# Livraison ClearCrypt V2

Date : 4 octobre 2026. Statut : tickets V2-001 à V2-018 terminés.

Ce document conserve une trace concise du découpage utilisé pour livrer
`CFENC002`. Les décisions applicables aux utilisateurs se trouvent dans le
[guide V2](guide-v2.md), les octets normatifs dans [format-v2.md](format-v2.md)
et les mesures dans [qualification-v2.md](qualification-v2.md).

| Ticket | Résultat livré | Statut |
| --- | --- | --- |
| V2-001 | contrat WHATWG Streams, contre-pression et cycle de vie | terminé |
| V2-002 | spécification binaire `CFENC002` | terminé |
| V2-003 | revue interne de la construction et limites par clé | terminé |
| V2-004 | types, constantes et codecs | terminé |
| V2-005 | lecteur incrémental borné | terminé |
| V2-006 | writer incrémental et destinations de test | terminé |
| V2-007 | chiffrement authentifié d'un enregistrement | terminé |
| V2-008 | déchiffrement authentifié d'un enregistrement | terminé |
| V2-009 | pipeline complet de chiffrement | terminé |
| V2-010 | pipeline complet de déchiffrement | terminé |
| V2-011 | API publique, progression et annulation | terminé |
| V2-012 | adaptateur de fichiers et CLI Node.js | terminé |
| V2-013 | intégration navigateur et Web Worker | terminé |
| V2-014 | vecteurs normatifs et vérificateur indépendant | terminé |
| V2-015 | tests adversariaux, propriétés et fuzzing | terminé |
| V2-016 | benchmark mémoire et débit reproductible | terminé |
| V2-017 | qualification 1, 10 et 100 Gio | terminé |
| V2-018 | documentation, compatibilité et contrôle du package | terminé |

## Résultat de la livraison

- V1 reste inchangé et ses anciennes archives restent lisibles.
- V2 chiffre et déchiffre séquentiellement avec une mémoire indépendante de la
  taille totale.
- Les fichiers Node.js sont publiés atomiquement par l'adaptateur et la CLI.
- Les vecteurs V1 et V2, les tests de types, les tests navigateur et le contenu
  exact du package font partie du contrôle de release.
- Des archives réelles de 1, 10 et 100 Gio ont réussi un round trip avec hash
  SHA-256 identique.
- Le format `CFENC002` est livré avec ClearCrypt 1.2.0.

## Évolutions séparées

Les sujets suivants demandent une nouvelle conception et ne font pas partie de
la première livraison V2 :

- reprise après crash ou interruption ;
- accès aléatoire et modification en place ;
- parallélisation de plusieurs blocs ;
- compression ou masquage de la taille ;
- conversion V1 vers V2 en streaming ;
- stockage, upload ou intégration à un fournisseur cloud.
