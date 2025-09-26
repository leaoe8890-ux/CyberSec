#!/usr/bin/env python3
"""
Sistema de Logs de Segurança
Sistema de Segurança Cibernética - CyberSec Guardian
"""

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import uuid
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import gzip
import shutil

class SecurityLogger:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.security_events = []
        self.log_handlers = {}
        self.setup_security_logging()
        
    def setup_security_logging(self):
        """Configura sistema de logging de segurança"""
        try:
            # Criar diretórios de logs
            logs_dir = Path('logs')
            security_logs_dir = logs_dir / 'security'
            audit_logs_dir = logs_dir / 'audit'
            
            for directory in [logs_dir, security_logs_dir, audit_logs_dir]:
                directory.mkdir(exist_ok=True)
            
            # Configurar diferentes tipos de logs
            self._setup_security_event_logger()
            self._setup_audit_logger()
            self._setup_access_logger()
            self._setup_threat_logger()
            self._setup_system_logger()
            
            self.logger.info("Sistema de logging de segurança configurado")
            
        except Exception as e:
            self.logger.error(f"Erro ao configurar logging de segurança: {e}")
    
    def _setup_security_event_logger(self):
        """Configura logger para eventos de segurança"""
        security_logger = logging.getLogger('security_events')
        security_logger.setLevel(logging.INFO)
        
        # Handler com rotação por tamanho
        handler = RotatingFileHandler(
            'logs/security/security_events.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=10,
            encoding='utf-8'
        )
        
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        security_logger.addHandler(handler)
        
        self.log_handlers['security_events'] = security_logger
    
    def _setup_audit_logger(self):
        """Configura logger para auditoria"""
        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(logging.INFO)
        
        # Handler com rotação diária
        handler = TimedRotatingFileHandler(
            'logs/audit/audit.log',
            when='midnight',
            interval=1,
            backupCount=365,  # Manter 1 ano
            encoding='utf-8'
        )
        
        formatter = logging.Formatter(
            '%(asctime)s | AUDIT | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        audit_logger.addHandler(handler)
        
        self.log_handlers['audit'] = audit_logger
    
    def _setup_access_logger(self):
        """Configura logger para acessos"""
        access_logger = logging.getLogger('access')
        access_logger.setLevel(logging.INFO)
        
        handler = RotatingFileHandler(
            'logs/security/access.log',
            maxBytes=5*1024*1024,  # 5MB
            backupCount=20,
            encoding='utf-8'
        )
        
        formatter = logging.Formatter(
            '%(asctime)s | ACCESS | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        access_logger.addHandler(handler)
        
        self.log_handlers['access'] = access_logger
    
    def _setup_threat_logger(self):
        """Configura logger para ameaças"""
        threat_logger = logging.getLogger('threats')
        threat_logger.setLevel(logging.WARNING)
        
        handler = RotatingFileHandler(
            'logs/security/threats.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=50,  # Manter mais logs de ameaças
            encoding='utf-8'
        )
        
        formatter = logging.Formatter(
            '%(asctime)s | THREAT | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        threat_logger.addHandler(handler)
        
        self.log_handlers['threats'] = threat_logger
    
    def _setup_system_logger(self):
        """Configura logger para eventos do sistema"""
        system_logger = logging.getLogger('system_security')
        system_logger.setLevel(logging.INFO)
        
        handler = TimedRotatingFileHandler(
            'logs/security/system.log',
            when='midnight',
            interval=1,
            backupCount=30,
            encoding='utf-8'
        )
        
        formatter = logging.Formatter(
            '%(asctime)s | SYSTEM | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        system_logger.addHandler(handler)
        
        self.log_handlers['system'] = system_logger
    
    def log_security_event(self, event_type, description, severity="INFO", source=None, additional_data=None):
        """Registra evento de segurança"""
        try:
            event_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat()
            hostname = socket.gethostname()
            
            # Criar estrutura do evento
            event = {
                'event_id': event_id,
                'timestamp': timestamp,
                'hostname': hostname,
                'event_type': event_type,
                'description': description,
                'severity': severity,
                'source': source or 'CyberSec Guardian',
                'additional_data': additional_data or {}
            }
            
            # Adicionar à lista de eventos
            self.security_events.append(event)
            
            # Log formatado
            log_message = self._format_security_event(event)
            
            # Registrar no logger apropriado
            security_logger = self.log_handlers.get('security_events')
            if security_logger:
                if severity == "CRITICAL":
                    security_logger.critical(log_message)
                elif severity == "HIGH":
                    security_logger.error(log_message)
                elif severity == "MEDIUM":
                    security_logger.warning(log_message)
                else:
                    security_logger.info(log_message)
            
            # Se for ameaça, registrar também no log de ameaças
            if event_type in ['THREAT_DETECTED', 'MALWARE', 'INTRUSION', 'ATTACK']:
                threat_logger = self.log_handlers.get('threats')
                if threat_logger:
                    threat_logger.warning(log_message)
            
            self.logger.debug(f"Evento de segurança registrado: {event_id}")
            return event_id
            
        except Exception as e:
            self.logger.error(f"Erro ao registrar evento de segurança: {e}")
            return None
    
    def log_audit_event(self, action, user=None, resource=None, result="SUCCESS", details=None):
        """Registra evento de auditoria"""
        try:
            event_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat()
            hostname = socket.gethostname()
            
            audit_event = {
                'event_id': event_id,
                'timestamp': timestamp,
                'hostname': hostname,
                'action': action,
                'user': user or 'system',
                'resource': resource,
                'result': result,
                'details': details or {}
            }
            
            # Log formatado
            log_message = self._format_audit_event(audit_event)
            
            audit_logger = self.log_handlers.get('audit')
            if audit_logger:
                audit_logger.info(log_message)
            
            return event_id
            
        except Exception as e:
            self.logger.error(f"Erro ao registrar evento de auditoria: {e}")
            return None
    
    def log_access_event(self, access_type, source_ip=None, user=None, resource=None, result="SUCCESS"):
        """Registra evento de acesso"""
        try:
            timestamp = datetime.now().isoformat()
            hostname = socket.gethostname()
            
            access_event = {
                'timestamp': timestamp,
                'hostname': hostname,
                'access_type': access_type,
                'source_ip': source_ip or 'localhost',
                'user': user or 'anonymous',
                'resource': resource or 'system',
                'result': result
            }
            
            log_message = self._format_access_event(access_event)
            
            access_logger = self.log_handlers.get('access')
            if access_logger:
                access_logger.info(log_message)
            
        except Exception as e:
            self.logger.error(f"Erro ao registrar evento de acesso: {e}")
    
    def log_threat_event(self, threat_type, description, severity="HIGH", source_ip=None, indicators=None):
        """Registra evento de ameaça"""
        try:
            event_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat()
            hostname = socket.gethostname()
            
            threat_event = {
                'event_id': event_id,
                'timestamp': timestamp,
                'hostname': hostname,
                'threat_type': threat_type,
                'description': description,
                'severity': severity,
                'source_ip': source_ip,
                'indicators': indicators or [],
                'hash': self._calculate_threat_hash(threat_type, description, source_ip)
            }
            
            log_message = self._format_threat_event(threat_event)
            
            threat_logger = self.log_handlers.get('threats')
            if threat_logger:
                if severity == "CRITICAL":
                    threat_logger.critical(log_message)
                else:
                    threat_logger.warning(log_message)
            
            # Também registrar como evento de segurança
            self.log_security_event(
                'THREAT_DETECTED',
                f"{threat_type}: {description}",
                severity,
                source_ip,
                threat_event
            )
            
            return event_id
            
        except Exception as e:
            self.logger.error(f"Erro ao registrar evento de ameaça: {e}")
            return None
    
    def log_system_event(self, event_type, description, component=None, status="INFO"):
        """Registra evento do sistema"""
        try:
            timestamp = datetime.now().isoformat()
            hostname = socket.gethostname()
            
            system_event = {
                'timestamp': timestamp,
                'hostname': hostname,
                'event_type': event_type,
                'component': component or 'system',
                'description': description,
                'status': status
            }
            
            log_message = self._format_system_event(system_event)
            
            system_logger = self.log_handlers.get('system')
            if system_logger:
                system_logger.info(log_message)
            
        except Exception as e:
            self.logger.error(f"Erro ao registrar evento do sistema: {e}")
    
    def _format_security_event(self, event):
        """Formata evento de segurança para log"""
        return (f"ID:{event['event_id']} | "
                f"TYPE:{event['event_type']} | "
                f"SEVERITY:{event['severity']} | "
                f"SOURCE:{event['source']} | "
                f"DESC:{event['description']}")
    
    def _format_audit_event(self, event):
        """Formata evento de auditoria para log"""
        return (f"ID:{event['event_id']} | "
                f"ACTION:{event['action']} | "
                f"USER:{event['user']} | "
                f"RESOURCE:{event['resource']} | "
                f"RESULT:{event['result']}")
    
    def _format_access_event(self, event):
        """Formata evento de acesso para log"""
        return (f"TYPE:{event['access_type']} | "
                f"IP:{event['source_ip']} | "
                f"USER:{event['user']} | "
                f"RESOURCE:{event['resource']} | "
                f"RESULT:{event['result']}")
    
    def _format_threat_event(self, event):
        """Formata evento de ameaça para log"""
        return (f"ID:{event['event_id']} | "
                f"THREAT:{event['threat_type']} | "
                f"SEVERITY:{event['severity']} | "
                f"IP:{event['source_ip']} | "
                f"HASH:{event['hash']} | "
                f"DESC:{event['description']}")
    
    def _format_system_event(self, event):
        """Formata evento do sistema para log"""
        return (f"TYPE:{event['event_type']} | "
                f"COMPONENT:{event['component']} | "
                f"STATUS:{event['status']} | "
                f"DESC:{event['description']}")
    
    def _calculate_threat_hash(self, threat_type, description, source_ip):
        """Calcula hash único para ameaça"""
        try:
            data = f"{threat_type}:{description}:{source_ip or 'unknown'}"
            return hashlib.sha256(data.encode()).hexdigest()[:16]
        except:
            return "unknown"
    
    def get_recent_events(self, hours=24, event_type=None, severity=None):
        """Obtém eventos recentes"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            recent_events = []
            
            for event in self.security_events:
                try:
                    event_time = datetime.fromisoformat(event['timestamp'])
                    if event_time >= cutoff_time:
                        # Filtrar por tipo se especificado
                        if event_type and event['event_type'] != event_type:
                            continue
                        
                        # Filtrar por severidade se especificado
                        if severity and event['severity'] != severity:
                            continue
                        
                        recent_events.append(event)
                except:
                    continue
            
            # Ordenar por timestamp (mais recente primeiro)
            recent_events.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return recent_events
            
        except Exception as e:
            self.logger.error(f"Erro ao obter eventos recentes: {e}")
            return []
    
    def get_security_statistics(self, hours=24):
        """Obtém estatísticas de segurança"""
        try:
            recent_events = self.get_recent_events(hours)
            
            stats = {
                'total_events': len(recent_events),
                'by_severity': {'CRITICAL': 0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFO':0},
                'by_type': {},
                'unique_sources': set(),
                'time_range': f"Últimas {hours} horas",
                'generated_at': datetime.now().isoformat()
            }
            
            for event in recent_events:
                # Contar por severidade
                severity = event.get('severity', 'INFO')
                if severity in stats['by_severity']:
                    stats['by_severity'][severity] += 1
                
                # Contar por tipo
                event_type = event.get('event_type', 'UNKNOWN')
                stats['by_type'][event_type] = stats['by_type'].get(event_type, 0) + 1
                
                # Coletar fontes únicas
                source = event.get('source', 'unknown')
                stats['unique_sources'].add(source)
            
            # Converter set para lista
            stats['unique_sources'] = list(stats['unique_sources'])
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar estatísticas: {e}")
            return {}
    
    def search_logs(self, query, log_type='security_events', max_results=100):
        """Busca nos logs de segurança"""
        try:
            results = []
            log_file = None
            
            # Determinar arquivo de log
            if log_type == 'security_events':
                log_file = 'logs/security/security_events.log'
            elif log_type == 'audit':
                log_file = 'logs/audit/audit.log'
            elif log_type == 'access':
                log_file = 'logs/security/access.log'
            elif log_type == 'threats':
                log_file = 'logs/security/threats.log'
            elif log_type == 'system':
                log_file = 'logs/security/system.log'
            
            if not log_file or not Path(log_file).exists():
                return results
            
            # Buscar no arquivo
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Buscar query nas linhas (últimas primeiro)
            for line in reversed(lines):
                if query.lower() in line.lower():
                    results.append(line.strip())
                    if len(results) >= max_results:
                        break
            
            return results
            
        except Exception as e:
            self.logger.error(f"Erro na busca de logs: {e}")
            return []
    
    def export_logs(self, start_date=None, end_date=None, log_types=None, format='json'):
        """Exporta logs para arquivo"""
        try:
            if not start_date:
                start_date = datetime.now() - timedelta(days=7)
            if not end_date:
                end_date = datetime.now()
            if not log_types:
                log_types = ['security_events', 'audit', 'threats']
            
            export_data = {
                'export_info': {
                    'generated_at': datetime.now().isoformat(),
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'log_types': log_types,
                    'format': format
                },
                'logs': {}
            }
            
            # Exportar cada tipo de log
            for log_type in log_types:
                export_data['logs'][log_type] = self._extract_logs_by_date(
                    log_type, start_date, end_date
                )
            
            # Salvar arquivo de exportação
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if format == 'json':
                export_file = f"logs/export_logs_{timestamp}.json"
                with open(export_file, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            else:
                export_file = f"logs/export_logs_{timestamp}.txt"
                with open(export_file, 'w', encoding='utf-8') as f:
                    f.write(f"Exportação de Logs - {datetime.now()}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for log_type, logs in export_data['logs'].items():
                        f.write(f"\n=== {log_type.upper()} ===\n")
                        for log_entry in logs:
                            f.write(f"{log_entry}\n")
            
            self.logger.info(f"Logs exportados para: {export_file}")
            return export_file
            
        except Exception as e:
            self.logger.error(f"Erro ao exportar logs: {e}")
            return None
    
    def _extract_logs_by_date(self, log_type, start_date, end_date):
        """Extrai logs por período de data"""
        try:
            log_files = {
                'security_events': 'logs/security/security_events.log',
                'audit': 'logs/audit/audit.log',
                'access': 'logs/security/access.log',
                'threats': 'logs/security/threats.log',
                'system': 'logs/security/system.log'
            }
            
            log_file = log_files.get(log_type)
            if not log_file or not Path(log_file).exists():
                return []
            
            matching_logs = []
            
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        # Extrair timestamp da linha (formato: YYYY-MM-DD HH:MM:SS)
                        timestamp_str = line.split(' | ')[0]
                        log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        
                        if start_date <= log_time <= end_date:
                            matching_logs.append(line.strip())
                    except:
                        continue
            
            return matching_logs
            
        except Exception as e:
            self.logger.error(f"Erro ao extrair logs por data: {e}")
            return []
    
    def cleanup_old_logs(self, days_to_keep=30):
        """Remove logs antigos"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            logs_dir = Path('logs')
            
            cleaned_files = 0
            
            # Procurar arquivos de log antigos
            for log_file in logs_dir.rglob('*.log.*'):
                try:
                    # Verificar data de modificação
                    file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
                    
                    if file_time < cutoff_date:
                        # Comprimir antes de remover se for grande
                        if log_file.stat().st_size > 1024*1024:  # > 1MB
                            self._compress_log_file(log_file)
                        
                        log_file.unlink()
                        cleaned_files += 1
                        
                except Exception as e:
                    self.logger.warning(f"Erro ao limpar {log_file}: {e}")
            
            self.logger.info(f"Limpeza de logs concluída: {cleaned_files} arquivos removidos")
            
            # Registrar evento de limpeza
            self.log_system_event(
                'LOG_CLEANUP',
                f"Limpeza automática removeu {cleaned_files} arquivos de log antigos",
                'log_manager',
                'SUCCESS'
            )
            
        except Exception as e:
            self.logger.error(f"Erro na limpeza de logs: {e}")
    
    def _compress_log_file(self, log_file):
        """Comprime arquivo de log antes da remoção"""
        try:
            compressed_file = f"{log_file}.gz"
            
            with open(log_file, 'rb') as f_in:
                with gzip.open(compressed_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            self.logger.debug(f"Log comprimido: {compressed_file}")
            
        except Exception as e:
            self.logger.warning(f"Erro ao comprimir log {log_file}: {e}")
    
    def get_log_summary(self):
        """Obtém resumo dos logs"""
        try:
            logs_dir = Path('logs')
            summary = {
                'total_log_files': 0,
                'total_size_mb': 0,
                'by_type': {},
                'oldest_log': None,
                'newest_log': None,
                'generated_at': datetime.now().isoformat()
            }
            
            oldest_time = None
            newest_time = None
            
            for log_file in logs_dir.rglob('*.log*'):
                try:
                    stat = log_file.stat()
                    size_mb = stat.st_size / (1024 * 1024)
                    mod_time = datetime.fromtimestamp(stat.st_mtime)
                    
                    summary['total_log_files'] += 1
                    summary['total_size_mb'] += size_mb
                    
                    # Categorizar por tipo
                    log_type = log_file.parent.name
                    if log_type not in summary['by_type']:
                        summary['by_type'][log_type] = {'files': 0, 'size_mb': 0}
                    
                    summary['by_type'][log_type]['files'] += 1
                    summary['by_type'][log_type]['size_mb'] += size_mb
                    
                    # Rastrear datas
                    if not oldest_time or mod_time < oldest_time:
                        oldest_time = mod_time
                        summary['oldest_log'] = str(log_file)
                    
                    if not newest_time or mod_time > newest_time:
                        newest_time = mod_time
                        summary['newest_log'] = str(log_file)
                        
                except Exception as e:
                    continue
            
            # Arredondar tamanhos
            summary['total_size_mb'] = round(summary['total_size_mb'], 2)
            for log_type in summary['by_type']:
                summary['by_type'][log_type]['size_mb'] = round(
                    summary['by_type'][log_type]['size_mb'], 2
                )
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar resumo de logs: {e}")
            return {}

# Exemplo de uso
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    security_logger = SecurityLogger()
    
    print("=== SISTEMA DE LOGS DE SEGURANÇA ===")
    
    # Exemplos de uso
    security_logger.log_security_event(
        'SYSTEM_START',
        'CyberSec Guardian iniciado',
        'INFO',
        'system'
    )
    
    security_logger.log_threat_event(
        'PORT_SCAN',
        'Scan de portas detectado',
        'HIGH',
        '192.168.1.100',
        ['port_22', 'port_80', 'port_443']
    )
    
    security_logger.log_access_event(
        'LOGIN',
        '127.0.0.1',
        'admin',
        'system',
        'SUCCESS'
    )
    
    # Obter estatísticas
    stats = security_logger.get_security_statistics(24)
    print(f"Estatísticas: {json.dumps(stats, indent=2, ensure_ascii=False)}")
    
    # Resumo dos logs
    summary = security_logger.get_log_summary()
    print(f"Resumo dos logs: {json.dumps(summary, indent=2, ensure_ascii=False)}")