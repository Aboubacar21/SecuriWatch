"""
Configuration de la connexion à la base de données PostgreSQL
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import QueuePool

# Configuration de la base de données
DATABASE_URL = "postgresql://securiwatch:securiwatch_dev_2025@localhost:5433/securiwatch"

# Créer le moteur SQLAlchemy avec pool de connexions
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,  # Vérifie la connexion avant utilisation
    echo=False  # Mettre à True pour voir les requêtes SQL
)

# Session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base pour les modèles ORM
Base = declarative_base()


def get_db():
    """
    Générateur de session de base de données
    Usage: with get_db() as db: ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_connection():
    """Teste la connexion à la base de données"""
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("Connexion à PostgreSQL réussie!")
            return True
    except Exception as e:
        print(f"Erreur de connexion: {e}")
        return False


if __name__ == "__main__":
    print("🔍 Test de connexion à PostgreSQL...")
    test_connection() 
