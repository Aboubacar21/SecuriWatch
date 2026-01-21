#!/usr/bin/env python3
"""
Collecteur de logs d'authentification avec sauvegarde en base de données
"""

import sys
import os

# Ajouter le chemin parent pour importer les modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import re
from datetime import datetime
from typing import List, Dict
import subprocess
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import Log


class AuthLogCollectorDB:
    """Collecte et sauvegarde les logs d'authentification en base de données"""
    
    def __init__(self, log_path: str = "/var/log/auth.log"):
        self.log_path = log_path
        
    def read_logs(self, lines: int = 100) -> List[str]:
        """Lit les N dernières lignes du fichier de log"""
        try:
            result = subprocess.run(
                ['sudo', 'tail', '-n', str(lines), self.log_path],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip().split('\n')
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lecture logs: {e}")
            return []
    
    def parse_log_line(self, line: str) -> Dict:
        """Parse une ligne de log et extrait les informations"""
        
        pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)'
        match = re.match(pattern, line)
        
        if not match:
            return None
            
        timestamp_str, hostname, process, pid, message = match.groups()
        
        # Convertir timestamp
        current_year = datetime.now().year
        timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        
        # Détection du type d'événement
        event_type = self._detect_event_type(process, message)
        
        # Extraction utilisateur
        user = self._extract_user(message)
        
        # Extraction IP
        ip_address = self._extract_ip(message)
        
        # Scoring de risque
        risk_score = self._calculate_risk(event_type, message)
        
        return {
            'timestamp': timestamp,
            'hostname': hostname,
            'process': process,
            'pid': int(pid) if pid else None,
            'event_type': event_type,
            'user_name': user,
            'ip_address': ip_address,
            'message': message,
            'risk_score': risk_score,
            'raw_log': line
        }
    
    def _detect_event_type(self, process: str, message: str) -> str:
        """Détecte le type d'événement de sécurité"""
        if 'sudo' in process.lower():
            return 'SUDO_COMMAND'
        elif 'session opened' in message:
            return 'SESSION_OPEN'
        elif 'session closed' in message:
            return 'SESSION_CLOSE'
        elif 'authentication failure' in message.lower():
            return 'AUTH_FAILURE'
        elif 'accepted' in message.lower():
            return 'AUTH_SUCCESS'
        elif 'invalid user' in message.lower():
            return 'INVALID_USER'
        elif 'cron' in process.lower():
            return 'CRON_JOB'
        else:
            return 'OTHER'
    
    def _extract_user(self, message: str) -> str:
        """Extrait le nom d'utilisateur du message"""
        patterns = [
            r'user (\w+)',
            r'for (\w+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)
        
        if 'root' in message.lower():
            return 'root'
        
        return 'unknown'
    
    def _extract_ip(self, message: str) -> str:
        """Extrait l'adresse IP si présente"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, message)
        return match.group(0) if match else None
    
    def _calculate_risk(self, event_type: str, message: str) -> int:
        """Calcule un score de risque (0-10)"""
        risk_scores = {
            'AUTH_FAILURE': 7,
            'INVALID_USER': 8,
            'SUDO_COMMAND': 5,
            'AUTH_SUCCESS': 2,
            'SESSION_OPEN': 3,
            'SESSION_CLOSE': 1,
            'CRON_JOB': 1,
            'OTHER': 2
        }
        
        base_score = risk_scores.get(event_type, 2)
        
        if 'failed' in message.lower():
            base_score += 2
        if 'root' in message.lower():
            base_score += 1
            
        return min(base_score, 10)
    
    def save_to_database(self, logs: List[Dict], db: Session) -> int:
        """Sauvegarde les logs en base de données"""
        saved_count = 0
        
        for log_data in logs:
            try:
                log = Log(**log_data)
                db.add(log)
                saved_count += 1
            except Exception as e:
                print(f"⚠️  Erreur sauvegarde log: {e}")
                continue
        
        try:
            db.commit()
            print(f"✅ {saved_count} logs sauvegardés en base de données")
        except Exception as e:
            db.rollback()
            print(f"❌ Erreur commit: {e}")
            saved_count = 0
        
        return saved_count
    
    def collect_and_save(self, lines: int = 50):
        """Collecte les logs et les sauvegarde en base"""
        print(f"🔍 Collecte des {lines} dernières lignes de {self.log_path}...\n")
        
        # Lire les logs
        raw_logs = self.read_logs(lines)
        parsed_logs = []
        
        for log_line in raw_logs:
            if log_line.strip():
                parsed = self.parse_log_line(log_line)
                if parsed:
                    parsed_logs.append(parsed)
        
        print(f"📊 {len(parsed_logs)} logs parsés\n")
        
        # Sauvegarder en base
        db = SessionLocal()
        try:
            saved = self.save_to_database(parsed_logs, db)
            
            # Afficher stats
            self.display_stats(db)
            
        finally:
            db.close()
    
    def display_stats(self, db: Session):
        """Affiche les statistiques de la base de données"""
        from sqlalchemy import func
        
        print("\n" + "="*60)
        print("📊 STATISTIQUES DE LA BASE DE DONNÉES")
        print("="*60)
        
        # Total de logs
        total = db.query(Log).count()
        print(f"Total de logs en base: {total}")
        
        # Par type d'événement
        print("\n🔹 Répartition par type:")
        event_counts = db.query(
            Log.event_type, 
            func.count(Log.id)
        ).group_by(Log.event_type).order_by(func.count(Log.id).desc()).all()
        
        for event_type, count in event_counts:
            print(f"   {event_type}: {count}")
        
        # Événements à haut risque
        high_risk = db.query(Log).filter(Log.risk_score >= 5).count()
        print(f"\n⚠️  Événements à risque (score ≥ 5): {high_risk}")
        
        # Top 5 des événements les plus risqués
        top_risks = db.query(Log).filter(Log.risk_score >= 5).order_by(
            Log.risk_score.desc(), Log.timestamp.desc()
        ).limit(5).all()
        
        if top_risks:
            print("\n🚨 TOP 5 ÉVÉNEMENTS À RISQUE:")
            for log in top_risks:
                print(f"   [{log.timestamp}] Risk={log.risk_score}/10")
                print(f"   Type: {log.event_type} | User: {log.user_name}")
                print(f"   Message: {log.message[:80]}...")
                print()


def main():
    """Fonction principale"""
    
    print("🛡️  SECURIWATCH - Collecteur avec Base de Données PostgreSQL")
    print("="*60)
    print()
    
    collector = AuthLogCollectorDB()
    collector.collect_and_save(lines=100)
    
    print("\n✅ Collecte terminée!")
    print("💡 Vous pouvez maintenant interroger la base avec SQL")


if __name__ == "__main__":
    main()
