#!/usr/bin/env python3
"""
CyberSec Guardian - Sistema Principal de Segurança Cibernética
Interface Principal e Orquestrador de Módulos
"""

import json
import logging
import os
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

# Adicionar o diretório modules ao path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

# Importar módulos do sistema
from location_tracker import LocationTracker
from hardware_tester import HardwareTester
from message_sender import MessageSender
from security_scanner import SecurityScanner

class CyberSecGuardian:
    def __init__(self, config_file=None):
        """Inicializa o sistema CyberSec Guardian"""
        self.config_file = config_file or "config/config.json"
        self.config = self.load_config()
        self.setup_logging()
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Inicializando CyberSec Guardian...")
        
        # Inicializar módulos
        self.location_tracker = LocationTracker(self.config)
        self.hardware_tester = HardwareTester(self.config)
        self.message_sender = MessageSender(self.config)
        self.security_scanner = SecurityScanner(self.config)
        
        # Estado do sistema
        self.is_monitoring = False
        self.monitoring_thread = None
        self.last_reports = {}
        
        self.logger.info("CyberSec Guardian inicializado com sucesso!")
    
    def load_config(self):
        """Carrega configuração do arquivo JSON"""
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                print(f"✅ Configuração carregada de: {config_path}")
                return config
            else:
                print(f"⚠️  Arquivo de configuração não encontrado: {config_path}")
                return self.get_default_config()
        except Exception as e:
            print(f"❌ Erro ao carregar configuração: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """Retorna configuração padrão"""
        return {
            "system": {
                "name": "CyberSec Guardian",
                "version": "1.0.0",
                "debug": True
            },
            "messaging": {
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "email_from": "security@company.com",
                "email_to": "admin@company.com"
            },
            "security": {
                "scan_ports": [21, 22, 23, 25, 53, 80, 110, 443, 993, 995],
                "timeout": 5,
                "max_threads": 50
            },
            "hardware": {
                "check_interval": 300,
                "temperature_threshold": 80,
                "memory_threshold": 90,
                "disk_threshold": 85
            }
        }
    
    def setup_logging(self):
        """Configura sistema de logging"""
        log_level = getattr(logging, self.config.get('logging', {}).get('level', 'INFO'))
        
        # Criar diretório de logs se não existir
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Configurar logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'cybersec_guardian.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def display_banner(self):
        """Exibe banner do sistema"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  CYBERSEC GUARDIAN 🛡️                    ║
║                                                              ║
║           Sistema Avançado de Segurança Cibernética         ║
║                        Versão 1.0.0                         ║
║                                                              ║
║  🔍 Localização Geográfica    🖥️  Testes de Hardware         ║
║  📧 Envio de Mensagens        🔒 Scans de Segurança          ║
║  📊 Relatórios Detalhados     ⚡ Monitoramento Contínuo      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def display_menu(self):
        """Exibe menu principal"""
        menu = """
┌─────────────────── MENU PRINCIPAL ───────────────────┐
│                                                      │
│  1. 📍 Obter Localização do Dispositivo             │
│  2. 🖥️  Executar Teste de Hardware                   │
│  3. 🔒 Executar Scan de Segurança                   │
│  4. 📧 Enviar Mensagem de Teste                     │
│  5. 📊 Gerar Relatório Completo                     │
│  6. ⚡ Iniciar Monitoramento Contínuo               │
│  7. 🛑 Parar Monitoramento                          │
│  8. 📋 Ver Status do Sistema                        │
│  9. ⚙️  Configurações                                │
│  0. 🚪 Sair                                         │
│                                                      │
└──────────────────────────────────────────────────────┘
        """
        print(menu)
    
    def get_device_location(self):
        """Obtém localização do dispositivo"""
        print("\n🔍 Obtendo localização do dispositivo...")
        
        try:
            report = self.location_tracker.get_full_location_report()
            
            print("\n📍 RELATÓRIO DE LOCALIZAÇÃO:")
            print("=" * 50)
            
            # Informações do dispositivo
            device_info = report.get('device_info', {})
            print(f"🖥️  Hostname: {device_info.get('hostname', 'N/A')}")
            print(f"💻 Sistema: {device_info.get('system', 'N/A')} {device_info.get('release', '')}")
            
            # Informações de rede
            network_info = report.get('network_info', {})
            print(f"🌐 IP Público: {network_info.get('public_ip', 'N/A')}")
            
            # Geolocalização
            geolocation = report.get('geolocation')
            if geolocation:
                print(f"🌍 País: {geolocation.get('country', 'N/A')}")
                print(f"🏙️  Cidade: {geolocation.get('city', 'N/A')}")
                print(f"🏢 ISP: {geolocation.get('isp', 'N/A')}")
                if geolocation.get('latitude') and geolocation.get('longitude'):
                    print(f"📐 Coordenadas: {geolocation['latitude']}, {geolocation['longitude']}")
            
            # Alertas de segurança
            security_notes = report.get('security_notes', [])
            if security_notes:
                print("\n⚠️  ALERTAS DE SEGURANÇA:")
                for note in security_notes:
                    print(f"   • {note}")
            
            # Salvar relatório
            self.save_report('location', report)
            
            # Enviar alerta se necessário
            if security_notes:
                alert_message = f"Alertas de localização detectados:\n" + "\n".join(f"• {note}" for note in security_notes)
                self.message_sender.broadcast_alert('location', alert_message, report)
            
        except Exception as e:
            print(f"❌ Erro ao obter localização: {e}")
            self.logger.error(f"Erro na localização: {e}")
    
    def run_hardware_test(self):
        """Executa teste de hardware"""
        print("\n🖥️  Executando teste completo de hardware...")
        print("⏳ Isso pode levar alguns minutos...")
        
        try:
            report = self.hardware_tester.run_full_hardware_test()
            
            print("\n🖥️  RELATÓRIO DE HARDWARE:")
            print("=" * 50)
            
            # Informações do sistema
            system_info = report.get('system_info', {})
            print(f"💻 Sistema: {system_info.get('system', 'N/A')} {system_info.get('release', '')}")
            print(f"🖥️  Hostname: {system_info.get('hostname', 'N/A')}")
            
            # Teste de CPU
            cpu_test = report.get('cpu_test', {})
            print(f"🔧 CPU Cores: {cpu_test.get('physical_cores', 'N/A')} físicos, {cpu_test.get('total_cores', 'N/A')} lógicos")
            print(f"📊 Uso de CPU: {cpu_test.get('cpu_usage_percent', 'N/A')}%")
            
            # Teste de Memória
            memory_test = report.get('memory_test', {})
            print(f"💾 RAM Total: {memory_test.get('total_ram_gb', 'N/A')} GB")
            print(f"📈 Uso de RAM: {memory_test.get('ram_usage_percent', 'N/A')}%")
            
            # Teste de Disco
            disk_test = report.get('disk_test', {})
            partitions = disk_test.get('partitions', [])
            if partitions:
                print("💿 Discos:")
                for partition in partitions[:3]:  # Mostrar apenas os 3 primeiros
                    print(f"   • {partition['device']}: {partition['used_gb']}GB/{partition['total_gb']}GB ({partition['usage_percent']}%)")
            
            # Saúde geral
            health = report.get('overall_health', 'UNKNOWN')
            health_score = report.get('health_score', 0)
            health_emoji = {'EXCELENTE': '🟢', 'BOM': '🟡', 'REGULAR': '🟠', 'RUIM': '🔴', 'CRÍTICO': '🚨'}.get(health, '❓')
            print(f"\n{health_emoji} Saúde Geral: {health} ({health_score}/100)")
            
            # Alertas
            alerts = report.get('alerts', [])
            if alerts:
                print("\n⚠️  ALERTAS:")
                for alert in alerts:
                    print(f"   • {alert}")
            
            print(f"\n⏱️  Duração do teste: {report.get('test_duration_seconds', 'N/A')} segundos")
            
            # Salvar relatório
            self.save_report('hardware', report)
            
            # Enviar alerta se necessário
            if alerts or health in ['RUIM', 'CRÍTICO']:
                alert_message = f"Problemas de hardware detectados. Saúde: {health}"
                if alerts:
                    alert_message += f"\nAlertas:\n" + "\n".join(f"• {alert}" for alert in alerts)
                self.message_sender.broadcast_alert('hardware', alert_message, report)
            
        except Exception as e:
            print(f"❌ Erro no teste de hardware: {e}")
            self.logger.error(f"Erro no teste de hardware: {e}")
    
    def run_security_scan(self):
        """Executa scan de segurança"""
        target = input("\n🎯 Digite o alvo para scan (IP ou domínio) [127.0.0.1]: ").strip()
        if not target:
            target = "127.0.0.1"
        
        print(f"\n🔒 Executando scan de segurança em: {target}")
        print("⏳ Isso pode levar alguns minutos...")
        
        try:
            report = self.security_scanner.run_comprehensive_scan(target)
            
            print(f"\n🔒 RELATÓRIO DE SEGURANÇA - {target}:")
            print("=" * 50)
            
            # Resumo
            summary = report.get('summary', {})
            print(f"🔍 Portas abertas: {summary.get('total_open_ports', 0)}")
            print(f"⚠️  Vulnerabilidades: {summary.get('total_vulnerabilities', 0)}")
            print(f"🚨 Críticas: {summary.get('critical_vulnerabilities', 0)}")
            print(f"🔴 Altas: {summary.get('high_vulnerabilities', 0)}")
            
            risk_level = summary.get('risk_level', 'Low')
            risk_emoji = {'Low': '🟢', 'Medium': '🟡', 'High': '🔴', 'Critical': '🚨'}.get(risk_level, '❓')
            print(f"\n{risk_emoji} Nível de Risco: {risk_level}")
            
            # Portas abertas
            port_scan = report.get('port_scan', {})
            open_ports = port_scan.get('open_ports', [])
            if open_ports:
                print(f"\n🔓 Portas Abertas ({len(open_ports)}):")
                for port in open_ports[:10]:  # Mostrar apenas as 10 primeiras
                    service = port.get('service', {}).get('name', 'Unknown')
                    print(f"   • {port['port']}/tcp - {service}")
            
            # Vulnerabilidades principais
            vuln_scan = report.get('vulnerability_scan', {})
            vulnerabilities = vuln_scan.get('vulnerabilities', [])
            if vulnerabilities:
                print(f"\n⚠️  Principais Vulnerabilidades:")
                for vuln in vulnerabilities[:5]:  # Mostrar apenas as 5 primeiras
                    severity_emoji = {'Critical': '🚨', 'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(vuln.get('severity'), '❓')
                    print(f"   {severity_emoji} {vuln.get('type', 'Unknown')} - Porta {vuln.get('port', 'N/A')}")
            
            print(f"\n⏱️  Duração do scan: {report.get('scan_duration_seconds', 'N/A')} segundos")
            
            # Salvar relatório
            self.save_report('security', report)
            
            # Enviar alerta se necessário
            if risk_level in ['High', 'Critical'] or summary.get('critical_vulnerabilities', 0) > 0:
                alert_message = f"Scan de segurança detectou riscos em {target}. Nível: {risk_level}"
                if vulnerabilities:
                    alert_message += f"\nVulnerabilidades críticas: {summary.get('critical_vulnerabilities', 0)}"
                self.message_sender.broadcast_alert('security', alert_message, report)
            
        except Exception as e:
            print(f"❌ Erro no scan de segurança: {e}")
            self.logger.error(f"Erro no scan de segurança: {e}")
    
    def send_test_message(self):
        """Envia mensagem de teste"""
        print("\n📧 Enviando mensagem de teste...")
        
        try:
            results = self.message_sender.send_test_messages()
            
            print("\n📧 RESULTADO DO ENVIO:")
            print("=" * 30)
            
            for channel, success in results.items():
                status_emoji = "✅" if success else "❌"
                status_text = "Sucesso" if success else "Falhou"
                print(f"{status_emoji} {channel.title()}: {status_text}")
            
            successful_channels = [channel for channel, success in results.items() if success]
            if successful_channels:
                print(f"\n✅ Mensagem enviada com sucesso via: {', '.join(successful_channels)}")
            else:
                print("\n❌ Falha no envio em todos os canais")
            
        except Exception as e:
            print(f"❌ Erro no envio de mensagem: {e}")
            self.logger.error(f"Erro no envio de mensagem: {e}")
    
    def generate_comprehensive_report(self):
        """Gera relatório completo do sistema"""
        print("\n📊 Gerando relatório completo do sistema...")
        print("⏳ Isso pode levar vários minutos...")
        
        try:
            comprehensive_report = {
                'report_id': f"CYBERSEC_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'timestamp': datetime.now().isoformat(),
                'system_name': self.config.get('system', {}).get('name', 'CyberSec Guardian'),
                'version': self.config.get('system', {}).get('version', '1.0.0'),
                'location_report': None,
                'hardware_report': None,
                'security_report': None,
                'summary': {},
                'recommendations': []
            }
            
            # 1. Relatório de localização
            print("📍 Obtendo localização...")
            comprehensive_report['location_report'] = self.location_tracker.get_full_location_report()
            
            # 2. Relatório de hardware
            print("🖥️  Testando hardware...")
            comprehensive_report['hardware_report'] = self.hardware_tester.run_full_hardware_test()
            
            # 3. Relatório de segurança (localhost)
            print("🔒 Executando scan de segurança...")
            comprehensive_report['security_report'] = self.security_scanner.run_comprehensive_scan('127.0.0.1')
            
            # 4. Gerar resumo
            comprehensive_report['summary'] = self.generate_summary(comprehensive_report)
            comprehensive_report['recommendations'] = self.generate_recommendations(comprehensive_report)
            
            # Salvar relatório completo
            self.save_report('comprehensive', comprehensive_report)
            
            # Exibir resumo
            self.display_comprehensive_summary(comprehensive_report)
            
            # Enviar alerta se necessário
            summary = comprehensive_report['summary']
            if summary.get('critical_issues', 0) > 0 or summary.get('risk_level') in ['High', 'Critical']:
                alert_message = f"Relatório completo detectou problemas críticos. Risco: {summary.get('risk_level', 'Unknown')}"
                self.message_sender.broadcast_alert('critical', alert_message, comprehensive_report)
            
        except Exception as e:
            print(f"❌ Erro na geração do relatório: {e}")
            self.logger.error(f"Erro na geração do relatório: {e}")
    
    def generate_summary(self, report):
        """Gera resumo do relatório completo"""
        summary = {
            'total_issues': 0,
            'critical_issues': 0,
            'hardware_health': 'Unknown',
            'security_risk': 'Unknown',
            'location_alerts': 0,
            'risk_level': 'Low'
        }
        
        # Analisar hardware
        hardware_report = report.get('hardware_report', {})
        if hardware_report:
            summary['hardware_health'] = hardware_report.get('overall_health', 'Unknown')
            hardware_alerts = len(hardware_report.get('alerts', []))
            summary['total_issues'] += hardware_alerts
            
            if hardware_report.get('overall_health') in ['CRÍTICO', 'RUIM']:
                summary['critical_issues'] += 1
        
        # Analisar segurança
        security_report = report.get('security_report', {})
        if security_report:
            security_summary = security_report.get('summary', {})
            summary['security_risk'] = security_summary.get('risk_level', 'Unknown')
            summary['total_issues'] += security_summary.get('total_vulnerabilities', 0)
            summary['critical_issues'] += security_summary.get('critical_vulnerabilities', 0)
        
        # Analisar localização
        location_report = report.get('location_report', {})
        if location_report:
            location_alerts = len(location_report.get('security_notes', []))
            summary['location_alerts'] = location_alerts
            summary['total_issues'] += location_alerts
        
        # Determinar risco geral
        if summary['critical_issues'] > 0:
            summary['risk_level'] = 'Critical'
        elif summary['hardware_health'] in ['RUIM', 'CRÍTICO'] or summary['security_risk'] in ['High', 'Critical']:
            summary['risk_level'] = 'High'
        elif summary['total_issues'] > 0:
            summary['risk_level'] = 'Medium'
        
        return summary
    
    def generate_recommendations(self, report):
        """Gera recomendações baseadas no relatório completo"""
        recommendations = []
        
        # Recomendações de hardware
        hardware_report = report.get('hardware_report', {})
        if hardware_report and hardware_report.get('alerts'):
            recommendations.append("🖥️  Resolver problemas de hardware identificados")
        
        # Recomendações de segurança
        security_report = report.get('security_report', {})
        if security_report:
            security_summary = security_report.get('summary', {})
            if security_summary.get('total_vulnerabilities', 0) > 0:
                recommendations.append("🔒 Corrigir vulnerabilidades de segurança")
            if security_summary.get('total_open_ports', 0) > 10:
                recommendations.append("🔓 Revisar portas abertas desnecessárias")
        
        # Recomendações de localização
        location_report = report.get('location_report', {})
        if location_report and location_report.get('security_notes'):
            recommendations.append("📍 Investigar alertas de localização")
        
        # Recomendações gerais
        recommendations.extend([
            "🔄 Manter sistema atualizado regularmente",
            "📊 Implementar monitoramento contínuo",
            "🛡️  Configurar firewall adequadamente",
            "💾 Realizar backups regulares",
            "🔐 Implementar autenticação forte"
        ])
        
        return recommendations
    
    def display_comprehensive_summary(self, report):
        """Exibe resumo do relatório completo"""
        print("\n📊 RESUMO DO RELATÓRIO COMPLETO:")
        print("=" * 60)
        
        summary = report.get('summary', {})
        
        # Status geral
        risk_level = summary.get('risk_level', 'Unknown')
        risk_emoji = {'Low': '🟢', 'Medium': '🟡', 'High': '🔴', 'Critical': '🚨'}.get(risk_level, '❓')
        print(f"{risk_emoji} Nível de Risco Geral: {risk_level}")
        
        # Estatísticas
        print(f"📊 Total de Problemas: {summary.get('total_issues', 0)}")
        print(f"🚨 Problemas Críticos: {summary.get('critical_issues', 0)}")
        
        # Status por módulo
        print(f"\n🖥️  Hardware: {summary.get('hardware_health', 'Unknown')}")
        print(f"🔒 Segurança: {summary.get('security_risk', 'Unknown')}")
        print(f"📍 Localização: {summary.get('location_alerts', 0)} alertas")
        
        # Recomendações principais
        recommendations = report.get('recommendations', [])
        if recommendations:
            print(f"\n💡 PRINCIPAIS RECOMENDAÇÕES:")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"   {i}. {rec}")
        
        print(f"\n📄 Relatório salvo em: reports/comprehensive_{report['report_id']}.json")
    
    def start_monitoring(self):
        """Inicia monitoramento contínuo"""
        if self.is_monitoring:
            print("⚠️  Monitoramento já está ativo!")
            return
        
        print("\n⚡ Iniciando monitoramento contínuo...")
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        # Iniciar processador de fila de mensagens
        self.message_sender.start_queue_processor()
        
        print("✅ Monitoramento iniciado com sucesso!")
        print("💡 O sistema irá verificar periodicamente:")
        print("   • Hardware a cada 5 minutos")
        print("   • Localização a cada 10 minutos")
        print("   • Segurança a cada 30 minutos")
    
    def stop_monitoring(self):
        """Para monitoramento contínuo"""
        if not self.is_monitoring:
            print("⚠️  Monitoramento não está ativo!")
            return
        
        print("\n🛑 Parando monitoramento...")
        
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        # Parar processador de fila de mensagens
        self.message_sender.stop_queue_processor()
        
        print("✅ Monitoramento parado com sucesso!")
    
    def _monitoring_loop(self):
        """Loop principal de monitoramento"""
        hardware_check_interval = self.config.get('hardware', {}).get('check_interval', 300)  # 5 minutos
        location_check_interval = 600  # 10 minutos
        security_check_interval = 1800  # 30 minutos
        
        last_hardware_check = 0
        last_location_check = 0
        last_security_check = 0
        
        self.logger.info("Loop de monitoramento iniciado")
        
        while self.is_monitoring:
            try:
                current_time = time.time()
                
                # Verificação de hardware
                if current_time - last_hardware_check >= hardware_check_interval:
                    self.logger.info("Executando verificação de hardware...")
                    try:
                        hardware_report = self.hardware_tester.run_full_hardware_test()
                        self.last_reports['hardware'] = hardware_report
                        
                        # Verificar alertas
                        alerts = hardware_report.get('alerts', [])
                        health = hardware_report.get('overall_health', 'UNKNOWN')
                        
                        if alerts or health in ['RUIM', 'CRÍTICO']:
                            alert_message = f"Monitoramento detectou problemas de hardware. Saúde: {health}"
                            if alerts:
                                alert_message += f"\nAlertas: {', '.join(alerts[:3])}"
                            
                            self.message_sender.add_to_queue('hardware', alert_message, hardware_report, 'high')
                        
                    except Exception as e:
                        self.logger.error(f"Erro na verificação de hardware: {e}")
                    
                    last_hardware_check = current_time
                
                # Verificação de localização
                if current_time - last_location_check >= location_check_interval:
                    self.logger.info("Executando verificação de localização...")
                    try:
                        location_report = self.location_tracker.get_full_location_report()
                        self.last_reports['location'] = location_report
                        
                        # Verificar alertas de segurança
                        security_notes = location_report.get('security_notes', [])
                        if security_notes:
                            alert_message = f"Monitoramento detectou alertas de localização: {', '.join(security_notes)}"
                            self.message_sender.add_to_queue('location', alert_message, location_report, 'normal')
                        
                    except Exception as e:
                        self.logger.error(f"Erro na verificação de localização: {e}")
                    
                    last_location_check = current_time
                
                # Verificação de segurança
                if current_time - last_security_check >= security_check_interval:
                    self.logger.info("Executando verificação de segurança...")
                    try:
                        security_report = self.security_scanner.run_comprehensive_scan('127.0.0.1')
                        self.last_reports['security'] = security_report
                        
                        # Verificar riscos
                        summary = security_report.get('summary', {})
                        risk_level = summary.get('risk_level', 'Low')
                        
                        if risk_level in ['High', 'Critical'] or summary.get('critical_vulnerabilities', 0) > 0:
                            alert_message = f"Monitoramento detectou riscos de segurança. Nível: {risk_level}"
                            priority = 'critical' if risk_level == 'Critical' else 'high'
                            self.message_sender.add_to_queue('security', alert_message, security_report, priority)
                        
                    except Exception as e:
                        self.logger.error(f"Erro na verificação de segurança: {e}")
                    
                    last_security_check = current_time
                
                # Aguardar antes da próxima iteração
                time.sleep(60)  # Verificar a cada minuto
                
            except Exception as e:
                self.logger.error(f"Erro no loop de monitoramento: {e}")
                time.sleep(60)
        
        self.logger.info("Loop de monitoramento finalizado")
    
    def show_system_status(self):
        """Exibe status do sistema"""
        print("\n📋 STATUS DO SISTEMA:")
        print("=" * 40)
        
        # Status geral
        print(f"🛡️  Sistema: {self.config.get('system', {}).get('name', 'CyberSec Guardian')}")
        print(f"📦 Versão: {self.config.get('system', {}).get('version', '1.0.0')}")
        print(f"⚡ Monitoramento: {'🟢 Ativo' if self.is_monitoring else '🔴 Inativo'}")
        
        # Status da fila de mensagens
        queue_status = self.message_sender.get_queue_status()
        print(f"📧 Fila de Mensagens: {queue_status['queue_size']} pendentes")
        
        # Últimos relatórios
        if self.last_reports:
            print(f"\n📊 ÚLTIMOS RELATÓRIOS:")
            for report_type, report in self.last_reports.items():
                timestamp = report.get('timestamp', 'N/A')
                if timestamp != 'N/A':
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        time_ago = datetime.now() - dt.replace(tzinfo=None)
                        minutes_ago = int(time_ago.total_seconds() / 60)
                        timestamp = f"{minutes_ago} min atrás"
                    except:
                        pass
                
                print(f"   • {report_type.title()}: {timestamp}")
        
        # Configurações principais
        print(f"\n⚙️  CONFIGURAÇÕES:")
        print(f"   • Intervalo Hardware: {self.config.get('hardware', {}).get('check_interval', 300)}s")
        print(f"   • Timeout Scan: {self.config.get('security', {}).get('timeout', 5)}s")
        print(f"   • Max Threads: {self.config.get('security', {}).get('max_threads', 50)}")
    
    def show_settings(self):
        """Exibe e permite alterar configurações"""
        print("\n⚙️  CONFIGURAÇÕES DO SISTEMA:")
        print("=" * 40)
        
        print("1. 📧 Configurações de Mensagens")
        print("2. 🔒 Configurações de Segurança")
        print("3. 🖥️  Configurações de Hardware")
        print("4. 📄 Ver Configuração Completa")
        print("5. 🔄 Recarregar Configuração")
        print("0. ↩️  Voltar")
        
        choice = input("\nEscolha uma opção: ").strip()
        
        if choice == '1':
            self.configure_messaging()
        elif choice == '2':
            self.configure_security()
        elif choice == '3':
            self.configure_hardware()
        elif choice == '4':
            print(json.dumps(self.config, indent=2, ensure_ascii=False))
        elif choice == '5':
            self.config = self.load_config()
            print("✅ Configuração recarregada!")
    
    def configure_messaging(self):
        """Configura opções de mensagens"""
        print("\n📧 CONFIGURAÇÕES DE MENSAGENS:")
        messaging_config = self.config.get('messaging', {})
        
        print(f"Email From: {messaging_config.get('email_from', 'N/A')}")
        print(f"Email To: {messaging_config.get('email_to', 'N/A')}")
        print(f"SMTP Server: {messaging_config.get('smtp_server', 'N/A')}")
        
        # Aqui você pode adicionar lógica para alterar configurações
        print("\n💡 Para alterar, edite o arquivo config/config.json")
    
    def configure_security(self):
        """Configura opções de segurança"""
        print("\n🔒 CONFIGURAÇÕES DE SEGURANÇA:")
        security_config = self.config.get('security', {})
        
        print(f"Portas para Scan: {security_config.get('scan_ports', [])}")
        print(f"Timeout: {security_config.get('timeout', 5)}s")
        print(f"Max Threads: {security_config.get('max_threads', 50)}")
        
        print("\n💡 Para alterar, edite o arquivo config/config.json")
    
    def configure_hardware(self):
        """Configura opções de hardware"""
        print("\n🖥️  CONFIGURAÇÕES DE HARDWARE:")
        hardware_config = self.config.get('hardware', {})
        
        print(f"Intervalo de Verificação: {hardware_config.get('check_interval', 300)}s")
        print(f"Limite Temperatura: {hardware_config.get('temperature_threshold', 80)}°C")
        print(f"Limite Memória: {hardware_config.get('memory_threshold', 90)}%")
        print(f"Limite Disco: {hardware_config.get('disk_threshold', 85)}%")
        
        print("\n💡 Para alterar, edite o arquivo config/config.json")
    
    def save_report(self, report_type, report_data):
        """Salva relatório em arquivo"""
        try:
            # Criar diretório de relatórios se não existir
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            # Nome do arquivo com timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_{timestamp}.json"
            filepath = reports_dir / filename
            
            # Salvar relatório
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            self.logger.info(f"Relatório {report_type} salvo em: {filepath}")
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar relatório: {e}")
    
    def run(self):
        """Executa o sistema principal"""
        try:
            self.display_banner()
            
            while True:
                self.display_menu()
                choice = input("\n🎯 Escolha uma opção: ").strip()
                
                if choice == '1':
                    self.get_device_location()
                elif choice == '2':
                    self.run_hardware_test()
                elif choice == '3':
                    self.run_security_scan()
                elif choice == '4':
                    self.send_test_message()
                elif choice == '5':
                    self.generate_comprehensive_report()
                elif choice == '6':
                    self.start_monitoring()
                elif choice == '7':
                    self.stop_monitoring()
                elif choice == '8':
                    self.show_system_status()
                elif choice == '9':
                    self.show_settings()
                elif choice == '0':
                    print("\n👋 Encerrando CyberSec Guardian...")
                    self.stop_monitoring()
                    break
                else:
                    print("❌ Opção inválida! Tente novamente.")
                
                input("\n⏸️  Pressione Enter para continuar...")
                
        except KeyboardInterrupt:
            print("\n\n🛑 Interrompido pelo usuário...")
            self.stop_monitoring()
        except Exception as e:
            print(f"\n❌ Erro crítico: {e}")
            self.logger.error(f"Erro crítico no sistema: {e}")
        finally:
            print("🔒 CyberSec Guardian finalizado.")

def main():
    """Função principal"""
    try:
        # Verificar se está sendo executado como root/admin (recomendado)
        if os.name != 'nt' and os.geteuid() != 0:
            print("⚠️  Aviso: Execute como root para funcionalidade completa")
        
        # Inicializar sistema
        guardian = CyberSecGuardian()
        guardian.run()
        
    except Exception as e:
        print(f"❌ Erro fatal: {e}")
        logging.error(f"Erro fatal: {e}")

if __name__ == "__main__":
    main()