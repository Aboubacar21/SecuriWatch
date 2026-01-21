# 🛡️ SecuriWatch - Plateforme d'Analyse de Sécurité Réseau

Système de détection d'anomalies et d'analyse de sécurité réseau avec Machine Learning.

## 🎯 Fonctionnalités

- ✅ Collecte automatique de logs (SSH, authentification, système)
- ✅ Détection d'événements de sécurité
- ✅ Scoring de risque intelligent (0-10)
- ✅ Stockage dans PostgreSQL
- ✅ Analyse et statistiques en temps réel
- 🚧 Machine Learning pour détection d'anomalies (à venir)
- 🚧 Dashboard web interactif (à venir)
- 🚧 Alertes automatiques (à venir)

## 🛠️ Stack Technique

**Backend:**
- Python 3.10+
- FastAPI
- SQLAlchemy
- PostgreSQL 15
- Pandas & NumPy
- Scikit-learn (ML)

**Infrastructure:**
- Docker & Docker Compose
- Redis

## 📊 Base de Données

7 tables créées :
- `logs` - Événements de sécurité collectés
- `incidents` - Incidents détectés
- `users` - Utilisateurs de l'application
- `alerts` - Alertes envoyées
- `detection_rules` - Règles configurables
- `daily_stats` - Statistiques quotidiennes
- `incident_logs` - Liaison logs/incidents

## 🚀 Installation

### Prérequis
- Python 3.10+
- Docker & Docker Compose
- Git

### Setup
```bash
# Cloner le repo
git clone https://github.com/votre-username/securiwatch.git
cd securiwatch

# Créer environnement virtuel Python
python3 -m venv venv
source venv/bin/activate

# Installer dépendances
pip install -r backend/requirements.txt

# Lancer PostgreSQL avec Docker
docker-compose up -d

# Tester le collecteur
python backend/app/collectors/auth_collector_db.py
```

## 📈 Utilisation

### Collecter les logs
```bash
python backend/app/collectors/auth_collector_db.py
```

### Interroger la base de données
```bash
sudo docker exec -it securiwatch-db psql -U securiwatch -d securiwatch
```

Exemples de requêtes SQL:
```sql
-- Voir les derniers logs
SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10;

-- Événements à risque élevé
SELECT * FROM logs WHERE risk_score >= 7;

-- Statistiques par type
SELECT event_type, COUNT(*) FROM logs GROUP BY event_type;
```

## 📁 Structure du Projet
```
securiwatch/
├── backend/
│   ├── app/
│   │   ├── collectors/
│   │   │   ├── auth_collector.py
│   │   │   └── auth_collector_db.py
│   │   ├── database.py
│   │   └── models.py
│   └── requirements.txt
├── scripts/
│   └── init_db.sql
├── docker-compose.yml
└── README.md
```

## 🎓 Développé par

**Aboubacar Sidiki Yattara**
- Email: sidikiyattara07@gmail.com
- LinkedIn: [aboubacar-sidiki-yattara](https://www.linkedin.com/in/aboubacar-sidiki-yattara943456239/)
- Étudiant en Master 1 Informatique - Université d'Artois

## 📝 Roadmap

- [x] Collecteur de logs SSH
- [x] Base de données PostgreSQL
- [x] Parsing et scoring de risque
- [ ] Modèles Machine Learning
- [ ] API REST FastAPI
- [ ] Dashboard web (NuxtJS)
- [ ] Système d'alertes
- [ ] Rapports PDF automatiques

## 📄 Licence

MIT License
