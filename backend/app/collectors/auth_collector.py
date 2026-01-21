#!/usr/bin/env python3
"""
Collecteur de logs d'authentification
Parse /var/log/auth.log et extrait les événements de sécurité
"""

import re
from datetime import datetime
from typing import List, Dict
import subprocess


class AuthLogCollector:
    """Collecte et parse les logs d'authentification Linux"""
    
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
        
        # Pattern général: Jan 21 22:04:35 hostname process[pid]: message
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
        
        # Extraction IP (si présente)
        ip_address = self._extract_ip(message)
        
        # Scoring de risque basique
        risk_score = self._calculate_risk(event_type, message)
        
        return {
            'timestamp': timestamp.isoformat(),
            'hostname': hostname,
            'process': process,
            'pid': pid,
            'event_type': event_type,
            'user': user,
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
            r'by \(uid=\d+\)',  # Pour root
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1) if match.lastindex else 'root'
        
        return 'unknown'
    
    def _extract_ip(self, message: str) -> str:
        """Extrait l'adresse IP si présente"""
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, message)
        
        return match.group(0) if match else None
    
    def _calculate_risk(self, event_type: str, message: str) -> int:
        """Calcule un score de risque basique (0-10)"""
        
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
        
        # Augmenter le score pour certains mots-clés
        if 'failed' in message.lower():
            base_score += 2
        if 'root' in message.lower():
            base_score += 1
            
        return min(base_score, 10)
    
    def collect(self, lines: int = 50) -> List[Dict]:
        """Collecte et parse les logs"""
        
        print(f"🔍 Collecte des {lines} dernières lignes de {self.log_path}...\n")
        
        raw_logs = self.read_logs(lines)
        parsed_logs = []
        
        for log_line in raw_logs:
            if log_line.strip():
                parsed = self.parse_log_line(log_line)
                if parsed:
                    parsed_logs.append(parsed)
        
        return parsed_logs
    
    def display_summary(self, logs: List[Dict]):
        """Affiche un résumé des logs collectés"""
        
        print(f"📊 RÉSUMÉ DE LA COLLECTE")
        print("=" * 60)
        print(f"Total d'événements: {len(logs)}")
        
        # Comptage par type
        event_counts = {}
        risk_events = []
        
        for log in logs:
            event_type = log['event_type']
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            if log['risk_score'] >= 5:
                risk_events.append(log)
        
        print("\n🔹 Répartition par type:")
        for event_type, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"   {event_type}: {count}")
        
        print(f"\n⚠️  Événements à risque (score ≥ 5): {len(risk_events)}")
        
        if risk_events:
            print("\n🚨 TOP 5 ÉVÉNEMENTS À RISQUE:")
            for log in sorted(risk_events, key=lambda x: x['risk_score'], reverse=True)[:5]:
                print(f"   [{log['timestamp']}] Risk={log['risk_score']}/10")
                print(f"   Type: {log['event_type']} | User: {log['user']}")
                print(f"   Message: {log['message'][:80]}...")
                print()


def main():
    """Fonction principale de test"""
    
    print("🛡️  SECURIWATCH - Collecteur de Logs d'Authentification")
    print("=" * 60)
    print()
    
    collector = AuthLogCollector()
    
    # Collecter les logs
    logs = collector.collect(lines=100)
    
    if logs:
        # Afficher le résumé
        collector.display_summary(logs)
        
        # Sauvegarder en JSON
        import json
        output_file = "auth_logs_collected.json"
        with open(output_file, 'w') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Logs sauvegardés dans: {output_file}")
        print(f"📁 Vous pouvez ouvrir ce fichier pour voir les données structurées")
    else:
        print("❌ Aucun log collecté")


if __name__ == "__main__":
    main()
