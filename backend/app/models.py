"""
Modèles SQLAlchemy pour la base de données
"""

from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, Boolean, Float, BigInteger
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.sql import func
from database import Base


class Log(Base):
    """Modèle pour la table logs"""
    __tablename__ = "logs"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp = Column(TIMESTAMP, nullable=False)
    hostname = Column(String(255))
    process = Column(String(100))
    pid = Column(Integer)
    event_type = Column(String(50), nullable=False)
    user_name = Column(String(100))
    ip_address = Column(INET)
    message = Column(Text)
    risk_score = Column(Integer)
    raw_log = Column(Text)
    collected_at = Column(TIMESTAMP, server_default=func.now())
    
    def __repr__(self):
        return f"<Log(id={self.id}, event_type={self.event_type}, risk_score={self.risk_score})>"
