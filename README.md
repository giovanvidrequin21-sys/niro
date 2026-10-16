# ATELIER sécurisé : connexion obligatoire pour accéder au site

Ce dossier contient le site **StG Diagnostic auto** protégé par un vrai serveur d'authentification.
Sans connexion, le serveur n'envoie **aucune ligne du site** : il renvoie la page de connexion.

Aucune dépendance à installer : le serveur n'utilise que les modules intégrés de Node.js 22 ou plus.

## Pourquoi un serveur est nécessaire

Une page HTML seule ne peut pas protéger son propre contenu : tout ce que le navigateur reçoit peut être lu.
Masquer des pages en JavaScript, ou comparer un mot de passe dans le navigateur, ne protège rien. La protection
doit se faire sur un serveur, qui décide s'il envoie le site ou non. C'est ce que fait `server.js`.

> La version du site publiée sur claude.ai ne peut pas avoir de comptes avec mot de passe : elle n'a pas de serveur.
> Sur claude.ai, l'accès se règle dans les paramètres de partage (qui peut ouvrir la page).

## Démarrage rapide (sur votre ordinateur)

```bash
cd ATELIER-securise
node server.js create-user votre_nom --admin     # demande le mot de passe (10 caractères minimum)
node server.js                                   # http://127.0.0.1:3000
```

Ouvrez http://127.0.0.1:3000 : vous arrivez sur la page de connexion.

## Comptes et inscription

Le mode se règle avec la variable `REGISTRATION` :

| Valeur | Effet |
|---|---|
| `invite` (défaut) | on s'inscrit avec un **code d'invitation** créé par vous, à usage limité et à durée limitée |
| `open` | inscription libre (limitée à 10 par adresse IP et par heure) |
| `closed` | pas d'inscription sur le site : vous créez les comptes en ligne de commande |

Commandes (elles agissent sur le serveur en marche, sans le redémarrer) :

```bash
node server.js create-user <nom> [--admin]
node server.js create-invite [--uses 3] [--days 7] [--note "pour Marc"]   # le code s'affiche une seule fois
node server.js reset-password <nom>        # change le mot de passe et ferme toutes les sessions du compte
node server.js revoke-sessions <nom>       # déconnecte le compte partout
node server.js delete-user <nom>
node server.js list-users
```

Règles : nom d'utilisateur de 3 à 32 caractères (minuscules, chiffres, point, tiret, tiret bas) ;
mot de passe de 10 à 128 caractères, ni trop courant, ni répétitif, ni contenant le nom d'utilisateur.

## Mise en ligne : HTTPS obligatoire

Sans HTTPS, les mots de passe circulent en clair sur le réseau. Le serveur affiche un avertissement sur la page
de connexion s'il est utilisé en HTTP hors ordinateur local. Deux solutions :

1. **Proxy HTTPS (recommandé).** Exemple avec Caddy, qui obtient le certificat tout seul :
   ```
   atelier.exemple.fr {
       reverse_proxy 127.0.0.1:3000
   }
   ```
   Lancez le serveur avec `HOST=127.0.0.1 TRUST_PROXY=1`. Le serveur ne doit alors être joignable **que** par le proxy.
2. **HTTPS direct** : `TLS_CERT` et `TLS_KEY` (chemins des fichiers du certificat).

En HTTPS, le cookie de session devient `__Host-sid` avec l'attribut `Secure`, et l'en-tête HSTS est envoyé.

Hébergement : n'importe quelle machine avec Node.js 22 et un **disque persistant** pour le dossier `DATA_DIR`
(beaucoup d'hébergeurs à disque temporaire perdraient les comptes à chaque redémarrage). Sauvegardez `data/`.
Exemple de lancement avec un fichier de réglages : `node --env-file=.env server.js` (voir `.env.example`).

## Ce qui est protégé, et comment

| Menace | Mesure |
|---|---|
| Lire le site sans compte | le serveur n'envoie le site qu'à une session valide ; sinon redirection vers `/login` sans contenu |
| Vol de la base de mots de passe | `scrypt` avec sel aléatoire par compte ; aucun mot de passe en clair, ni dans les fichiers, ni dans les journaux |
| Vol du jeton de session | jeton aléatoire de 256 bits ; seul son hash est stocké ; cookie `HttpOnly` (invisible pour JavaScript), `SameSite=Strict` |
| Session volée ou oubliée | expiration après 12 h d'inactivité, 7 jours maximum ; fermeture côté serveur à la déconnexion, au changement de mot de passe et par `revoke-sessions` |
| Fixation de session | un nouveau jeton est toujours émis à la connexion |
| Devinette de mots de passe | 5 échecs verrouillent le compte (15 minutes, doublé à chaque échec suivant) ; 30 échecs par adresse IP et par 10 minutes ; même réponse pour un compte inconnu ou un mauvais mot de passe |
| CSRF (requête forgée depuis un autre site) | JSON uniquement, en-tête personnalisé obligatoire, contrôle de l'origine, cookie `SameSite=Strict` |
| Injection de script (XSS) | politique CSP à jeton unique par réponse, sans `unsafe-inline` pour les scripts ; aucune donnée du serveur n'est insérée comme HTML |
| Intégration dans une page tierce | `X-Frame-Options: DENY` et `frame-ancestors 'none'` |
| Lecture de fichiers du serveur | aucune URL n'est convertie en chemin de fichier |
| Cache d'un navigateur partagé | `Cache-Control: no-store` : le bouton « retour » après déconnexion n'affiche pas le site |

## Ce que ce serveur ne fait PAS

- **Pas d'e-mail** : pas de vérification d'adresse, pas de « mot de passe oublié » par e-mail (cela demande un service d'envoi de messages).
  La réinitialisation se fait par vous, avec `reset-password`.
- **Pas de double authentification**, pas de CAPTCHA.
- **Stockage simple** : des fichiers JSON, adaptés à quelques centaines de comptes. Au-delà, une vraie base de données est préférable.
- **Pas de protection contre une attaque massive distribuée** : cela relève d'un service placé devant le serveur.
- **Aucun audit externe.** Les tests de ce dossier vérifient les mesures ci-dessus ; une relecture par un spécialiste est conseillée avant un usage sensible.
- **L'Atelier Expert** (onglet réservé) dépend de la plateforme claude.ai et **ne fonctionne pas** dans cette version : il faudrait lui écrire un stockage propre.
- Les données du véhicule restent dans le navigateur, séparées par compte (clés `u<numéro>:…`), mais « Se déconnecter » ne les efface pas :
  sur un ordinateur partagé, videz aussi les données du site dans le navigateur.

## Tests

```bash
node tests/auth-tests.js
```

Les tests démarrent de vrais serveurs et les attaquent : accès sans connexion, jetons falsifiés, requêtes d'un autre site,
force brute, traversée de répertoire, expiration, révocation, fixation de session, stockage des mots de passe, HTTPS, commandes
pendant que le serveur tourne.

## Fichiers

- `server.js` : le serveur (authentification, sessions, protection du site, commandes)
- `site/index.html` : le site (identique à la version principale ; il se branche sur la session quand il est servi par ce serveur)
- `site/login.html` : la page de connexion et d'inscription
- `tests/auth-tests.js` : les tests de sécurité
"# niro" 
