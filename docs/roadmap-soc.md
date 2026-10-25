# Feuille de route SOC

Pistes pour augmenter la valeur d'elastalert3 dans un SOC : contenu de détection, contexte, réduction du bruit,
fiabilité 24/7. Toutes sont additives et ne cassent pas le contrat ElastAlert 2 (nouvelles clés, nouveaux types de
règle, modules `rust.*`, champs writeback ajoutés uniquement).

## Priorité 1 : forte valeur SOC

### 1. Import natif de règles Sigma

- `type: sigma` ou `sigma_file:` : conversion au chargement vers Query DSL, EQL ou ES|QL.
- Mapping de champs configurable (ECS, Winlogbeat, champs maison).
- Les `tags` ATT&CK et le `level` Sigma remontent dans l'alerte.
- Argument d'adoption majeur : des milliers de règles prêtes (SigmaHQ) utilisables directement par le moteur.

### 2. Métadonnées de détection et sortie ECS

- Clés de règle `severity`, `risk_score`, `mitre: [T1110.001]`, `owner`, `runbook_url`, recopiées dans le document
  `elastalert` (champs additifs).
- Écriture des alertes au format ECS (`event.kind: alert`, `threat.technique.*`, `rule.*`), consommables par Kibana,
  Elastic Security et OpenSearch Security Analytics.
- `validate --coverage` : matrice des techniques ATT&CK couvertes par les règles.

### 3. Enrichissement dynamique

Au-delà de la table statique de `rust.lookup` (point d'extension : `REGISTRY` dans `src/enhancements.rs`) :

- `rust.ioc_lookup` : IOC depuis CSV/fichier, MISP ou OpenCTI, rechargés à chaud ; IP, CIDR, domaine, hash.
- `rust.cidr` : classification d'IP (interne, externe, DMZ, VPN).
- `rust.geoip` : base MaxMind `.mmdb` locale (pays, ASN).
- `rust.es_lookup` : jointure sur un autre index (CMDB, annuaire AD, criticité des assets), cache LRU avec TTL.

### 4. Risk-Based Alerting (`type: risk`)

- Une règle attribue un score à une entité (`risk_entity: user.name`, `risk_score: 20`) sans alerter directement.
- Une règle de risque cumule les scores par entité sur une fenêtre et alerte au-dessus d'un seuil, ou quand plusieurs
  tactiques ATT&CK distinctes apparaissent.
- Principal levier contre la fatigue d'alerte ; prolonge `correlation` et `EventWindow`.

### 5. Méta-règles : corrélation sur les alertes

- Une règle prend en entrée les matches d'autres règles (bus interne ou index writeback).
- Exemples : brute force puis login réussi puis création de compte sur le même hôte en 30 min ; 3 règles distinctes
  sur le même utilisateur en 1 h.
- Extensions de `correlation` : ordre strict des étapes (`sequence: true`), seuil par étape (`min_count`).

### 6. Haute disponibilité

- Aujourd'hui deux instances sur le même index writeback alertent deux fois.
- Élection de leader par un bail dans l'index writeback (`if_seq_no` / `if_primary_term`, renouvelé toutes les N s) ;
  l'instance passive reprend via la récupération existante au démarrage (`src/main.rs`).
- Version avancée : partitionnement des règles par hash entre instances.

## Priorité 2 : detection engineering et exploitation

### 7. Detection-as-code : tests hors ligne

- `elastalert test-rule --events fixtures.ndjson --expect expected.yaml` : exécute le moteur (`src/types.rs`) sans
  Elasticsearch et vérifie les matches attendus.
- Cas positifs et négatifs par règle, intégrables en CI.

### 8. Rapport de tuning et de bruit

- `--start ... --dry-run --report` : par règle, nombre d'alertes, top des valeurs de `query_key`, volume estimé
  après `realert` et agrégation.
- Sortie CSV ou JSON, pour calibrer une règle avant mise en production.

### 9. Exceptions gérées

- Fichier ou index d'exceptions par règle : condition, justification, auteur, date d'expiration.
- Réactivation automatique à expiration, journalisée ; plus auditable que des `filter` négatifs dispersés.

### 10. Santé des sources et observabilité

- Métriques Prometheus : `elastalert_rule_lag_seconds`, dernier run réussi, histogramme de durée des requêtes,
  taille des fenêtres en mémoire (aujourd'hui 8 compteurs dans `src/metrics.rs`).
- Détection automatique d'une source muette (index ou `event.dataset` sans données depuis X), sans écrire une règle
  `flatline` par source.

### 11. ChatOps : acquittement et silence depuis l'alerte

- Boutons Slack, Teams, Mattermost : acquitter, silence 24 h sur l'entité, faux positif.
- Endpoint HTTP qui écrit le silence (`Silences` est déjà en mémoire).
- Escalade si l'alerte n'est pas acquittée en N minutes.

### 12. Routage par sévérité

- Bloc global `routing:` (par exemple `severity >= high` vers PagerDuty et TheHive, `low` vers l'index seul), sans
  dupliquer les `alert:` dans chaque règle.
- Création automatique d'observables TheHive / IRIS à partir des champs ECS (IP, hash, utilisateur).

## Priorité 3 : couverture et plateforme

13. **AWS SigV4 vers OpenSearch** (non supporté aujourd'hui) : la signature existe déjà pour SNS/SQS/SES
    (`src/alerters/aws.rs`).
14. **Multi-cluster** (`es_host` par règle, rejeté aujourd'hui) : utile aux MSSP multi-tenants, avec un tag `tenant`
    dans le writeback.
15. **Secrets externes** : `${file:/run/secrets/x}`, Vault, au lieu de mots de passe dans le YAML (point d'entrée :
    `expand_env` dans `src/config.rs`).
16. **Anomalie légère** (`type: baseline`) : z-score ou EWMA par entité avec saisonnalité heure/jour, plus robuste que
    `spike`.
17. **API REST de gestion** : état des règles, silences, relance, rechargement ; base pour une interface web.
18. **Pack de règles fourni** : AD, Linux auth, M365, pare-feu, mappées ATT&CK et testées via le point 7.

## Ordre recommandé

1. Sigma (1) et métadonnées / ECS (2) : adoption et intégration à l'écosystème.
2. Enrichissement (3) et tests hors ligne (7) : qualité des alertes et workflow d'ingénierie.
3. Risk-Based Alerting (4) et méta-règles (5) : différenciation face à ElastAlert 2.
4. Haute disponibilité (6) : prérequis de production pour un SOC 24/7.
