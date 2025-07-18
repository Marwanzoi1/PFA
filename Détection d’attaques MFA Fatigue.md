
## 🔐 **Détection d’attaques par MFA Fatigue**

(Projet très pertinent et en phase avec les problèmes actuels dans la cybersécurité)

---

## 🧠 **Résumé du projet**

Le but est de **simuler et détecter des attaques par fatigue MFA** (Multi-Factor Authentication), un type d’attaque de plus en plus courant où un attaquant bombarde un utilisateur de requêtes MFA dans l’espoir qu’il accepte par fatigue ou par erreur.

---

## 🎯 **Objectifs pédagogiques**

* Comprendre le **fonctionnement des MFA (OTP, push, passkeys…)**
* Identifier des **patterns anormaux d’authentification**
* Proposer une **solution intelligente de détection de comportements suspects**
* Améliorer l’**UX** ou la **sécurité du flux MFA**

---

## 🧰 **Stack technique recommandée**

| Composant                | Description                                                                 |
| ------------------------ | --------------------------------------------------------------------------- |
| **Backend**              | Python (Flask/FastAPI) ou Node.js (Express)                                 |
| **Gestion IAM/MFA**      | Keycloak (self-hosted) ou Auth0 (cloud)                                     |
| **Logs & Audit**         | Keycloak logs, journaux NGINX, base de données d’événements (SQLite, Mongo) |
| **IA / Heuristique**     | Python + Pandas, Scikit-learn ou simplement règles personnalisées           |
| **Frontend (optionnel)** | React.js ou simple HTML/CSS + JS                                            |
| **Monitoring**           | Grafana / Streamlit / Kibana pour visualiser les alertes                    |

---

## 📂 **Livrables attendus**

* 🔐 Un simulateur d’environnement MFA (login, push, etc.)
* 🧠 Une logique de détection d’attaque (règles + éventuellement IA)
* 📊 Dashboard d’alertes ou rapport d’activité
* 📝 Rapport PFA (explication attaque, mesures, résultats, code)

---

## 🧪 **Fonctionnalités clés à développer**

### 1. **Flux MFA normal vs attaque**

* Flux **normal** : 1-2 tentatives d’authentification, bon timing
* Flux **anormal** : 10 tentatives en 5 minutes, de plusieurs IP, à des heures inhabituelles

### 2. **Détection des signaux faibles**

* Trop de requêtes MFA pour un même utilisateur
* Réponse très rapide à des push (ex. 1 seconde = suspect)
* Tentatives à des heures atypiques (ex : 3h du matin)
* Authentifications depuis pays différents (géolocalisation IP)

### 3. **Alertes**

* Générer une **alerte temps réel** dès qu’un seuil est franchi
* Option : notifier administrateur ou bloquer compte temporairement

---

## 🧠 **Approches de détection**

| Méthode                   | Description                                                          |
| ------------------------- | -------------------------------------------------------------------- |
| **Heuristique simple**    | "Si plus de 5 MFA en 10 min → alerte"                                |
| **Détection d’anomalies** | Isolation Forest, One-Class SVM, etc. (ML non-supervisé)             |
| **Score de risque**       | Chaque événement reçoit un score ; si total dépasse un seuil, alerte |
| **UX + AI combinée**      | Push intelligent avec délai, authentification adaptative             |

---

## 📈 **Dashboard ou reporting**

* Tableau avec les utilisateurs + nb MFA
* Graphiques temps réel (courbe de requêtes MFA)
* Filtres : utilisateur, heure, pays, IP
* Historique des alertes déclenchées
* Option : rapport PDF ou JSON exportable

---

## 🗺️ **Architecture du projet**

```
[🧑 Utilisateur] ─▶ [Frontend Login UI] ─▶ [Keycloak/Auth0] ─▶ [Logs API / DB]
                                              │
                                              ▼
                         [🧠 Analyse Python ou Règles de détection]
                                              │
                                              ▼
                                   [📊 Dashboard / Alertes]
```

---

## 🛠️ **Environnement requis pour PC local (PC 2)**

| Logiciel / outil       | Détails                               | Recommandé ? |
| ---------------------- | ------------------------------------- | ------------ |
| **Docker Desktop**     | Pour faire tourner Keycloak si besoin | ✅            |
| **Python 3.10+**       | Pour le backend et l’analyse IA       | ✅            |
| **Visual Studio Code** | Pour le développement                 | ✅            |
| **SQLite ou MongoDB**  | Pour stocker les logs MFA             | ✅            |
| **Wireshark (option)** | Pour capturer les échanges réseau     | 🟡 (avancé)  |

💡 Si tu n’as pas Docker, tu peux aussi utiliser **Auth0** (cloud, plan gratuit).

---

## 🚀 **Extensions possibles**

* Ajout de **méthodes d’authentification alternatives** (biométrie, WebAuthn)
* Intégration avec **SIEM comme Wazuh ou ELK**
* Génération automatique de **recommandations UX**
* Implémenter une **version mobile** pour le push MFA

---

## 🧩 Étapes proposées (plan sur 6–8 semaines)

| Semaine | Tâche principale                                |
| ------- | ----------------------------------------------- |
| 1       | Étude MFA fatigue + installation Keycloak/Auth0 |
| 2       | Simulateur MFA frontend/backend                 |
| 3       | Collecte et stockage des logs                   |
| 4       | Implémentation des règles de détection          |
| 5       | Création dashboard de visualisation             |
| 6       | Tests : utilisateurs, cas d’attaque, UX         |
| 7       | Rapport final, version portable                 |
| 8       | Soutenance / démo vidéo                         |

---

