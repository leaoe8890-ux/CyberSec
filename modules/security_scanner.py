#!/usr/bin/env python3
"""
Módulo de Testes de Segurança de Rede
Sistema de Segurança Cibernética - CyberSec Guardian
"""

import socket
import subprocess
import threading
import time
import json
import logging
import hashlib
import ssl
import requests
from datetime import datetime
import concurrent.futures
import ipaddress
import platform
import re
import uuid

class SecurityScanner:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.scan_results = {}
        self.vulnerabilities = []
        
    def port_scan(self, target, ports=None, timeout=3):
        """Realiza scan de portas em um alvo"""
        if ports is None:
            ports = self.config.get('security', {}).get('scan_ports', [21, 22, 23, 25, 53, 80, 110, 443, 993, 995])
        
        self.logger.info(f"Iniciando scan de portas em {target}")
        
        open_ports = []
        closed_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    # Tentar identificar o serviço
                    service_info = self._identify_service(target, port)
                    open_ports.append({
                        'port': port,
                        'state': 'open',
                        'service': service_info
                    })
                else:
                    closed_ports.append({
                        'port': port,
                        'state': 'closed'
                    })
                
                sock.close()
                
            except Exception as e:
                closed_ports.append({
                    'port': port,
                    'state': 'filtered',
                    'error': str(e)
                })
        
        # Usar threads para scan paralelo
        max_threads = self.config.get('security', {}).get('max_threads', 50)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(scan_port, ports)
        
        scan_result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': sorted(open_ports, key=lambda x: x['port']),
            'closed_ports': sorted(closed_ports, key=lambda x: x['port']),
            'total_ports_scanned': len(ports),
            'open_ports_count': len(open_ports),
            'scan_duration': 0
        }
        
        self.logger.info(f"Scan concluído: {len(open_ports)} portas abertas de {len(ports)} testadas")
        
        return scan_result
    
    def _identify_service(self, host, port):
        """Identifica o serviço rodando em uma porta"""
        try:
            # Mapeamento básico de portas para serviços
            common_services = {
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S',
                3389: 'RDP',
                5432: 'PostgreSQL',
                3306: 'MySQL',
                1433: 'MSSQL',
                6379: 'Redis',
                27017: 'MongoDB'
            }
            
            service_name = common_services.get(port, 'Unknown')
            
            # Tentar banner grabbing para mais informações
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, port))
                
                # Enviar requisição HTTP se for porta web
                if port in [80, 443, 8080, 8443]:
                    request = b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
                    sock.send(request)
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                if banner:
                    return {
                        'name': service_name,
                        'banner': banner[:200],  # Limitar tamanho do banner
                        'version': self._extract_version(banner)
                    }
                    
            except:
                pass
            
            return {'name': service_name}
            
        except Exception as e:
            return {'name': 'Unknown', 'error': str(e)}
    
    def _extract_version(self, banner):
        """Extrai informações de versão do banner"""
        try:
            # Padrões comuns para extrair versões
            patterns = [
                r'Server: ([^\r\n]+)',
                r'OpenSSH[_\s]+([\d\.]+)',
                r'Apache[/\s]+([\d\.]+)',
                r'nginx[/\s]+([\d\.]+)',
                r'Microsoft-IIS[/\s]+([\d\.]+)',
                r'vsftpd[_\s]+([\d\.]+)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    return match.group(1)
            
            return None
            
        except:
            return None
    
    def network_discovery(self, network_range=None):
        """Descobre hosts ativos na rede"""
        if not network_range:
            # Tentar descobrir a rede local automaticamente
            network_range = self._get_local_network()
        
        self.logger.info(f"Descobrindo hosts na rede: {network_range}")
        
        active_hosts = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            def ping_host(ip):
                try:
                    ip_str = str(ip)
                    
                    # Usar ping do sistema
                    if platform.system().lower() == 'windows':
                        cmd = ['ping', '-n', '1', '-w', '1000', ip_str]
                    else:
                        cmd = ['ping', '-c', '1', '-W', '1', ip_str]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        # Tentar obter hostname
                        try:
                            hostname = socket.gethostbyaddr(ip_str)[0]
                        except:
                            hostname = None
                        
                        active_hosts.append({
                            'ip': ip_str,
                            'hostname': hostname,
                            'response_time': self._extract_ping_time(result.stdout)
                        })
                        
                except Exception as e:
                    pass
            
            # Limitar a 254 hosts para evitar scans muito longos
            hosts_to_scan = list(network.hosts())[:254]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                executor.map(ping_host, hosts_to_scan)
            
        except Exception as e:
            self.logger.error(f"Erro na descoberta de rede: {e}")
        
        discovery_result = {
            'network_range': network_range,
            'timestamp': datetime.now().isoformat(),
            'active_hosts': sorted(active_hosts, key=lambda x: ipaddress.ip_address(x['ip'])),
            'total_hosts_found': len(active_hosts)
        }
        
        self.logger.info(f"Descoberta concluída: {len(active_hosts)} hosts ativos encontrados")
        
        return discovery_result
    
    def _get_local_network(self):
        """Obtém a rede local automaticamente"""
        try:
            # Obter IP local
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            
            # Assumir /24 para a rede local
            network_parts = local_ip.split('.')
            network_parts[3] = '0'
            network = '.'.join(network_parts) + '/24'
            
            return network
            
        except:
            return '192.168.1.0/24'  # Fallback
    
    def _extract_ping_time(self, ping_output):
        """Extrai tempo de resposta do ping"""
        try:
            # Padrões para diferentes sistemas
            patterns = [
                r'time[=<](\d+\.?\d*)ms',
                r'time=(\d+\.?\d*)ms',
                r'(\d+\.?\d*)ms'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, ping_output, re.IGNORECASE)
                if match:
                    return float(match.group(1))
            
            return None
            
        except:
            return None
    
    def ssl_certificate_check(self, hostname, port=443):
        """Verifica certificado SSL/TLS"""
        try:
            self.logger.info(f"Verificando certificado SSL de {hostname}:{port}")
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Analisar certificado
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                        'san': cert.get('subjectAltName', []),
                        'is_valid': True,
                        'days_until_expiry': 0,
                        'warnings': []
                    }
                    
                    # Verificar validade
                    try:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.now()).days
                        cert_info['days_until_expiry'] = days_until_expiry
                        
                        if days_until_expiry < 30:
                            cert_info['warnings'].append(f"Certificado expira em {days_until_expiry} dias")
                        
                        if days_until_expiry < 0:
                            cert_info['is_valid'] = False
                            cert_info['warnings'].append("Certificado expirado")
                            
                    except Exception as e:
                        cert_info['warnings'].append(f"Erro ao verificar expiração: {e}")
                    
                    # Verificar algoritmo de assinatura
                    weak_algorithms = ['md5', 'sha1']
                    sig_alg = cert_info['signature_algorithm'].lower()
                    for weak_alg in weak_algorithms:
                        if weak_alg in sig_alg:
                            cert_info['warnings'].append(f"Algoritmo de assinatura fraco: {cert_info['signature_algorithm']}")
                    
                    return cert_info
                    
        except Exception as e:
            self.logger.error(f"Erro na verificação SSL: {e}")
            return {
                'error': str(e),
                'is_valid': False,
                'warnings': [f"Falha na conexão SSL: {e}"]
            }
    
    def vulnerability_scan(self, target):
        """Realiza scan básico de vulnerabilidades"""
        self.logger.info(f"Iniciando scan de vulnerabilidades em {target}")
        
        vulnerabilities = []
        
        # Scan de portas primeiro
        port_scan_result = self.port_scan(target)
        
        for port_info in port_scan_result['open_ports']:
            port = port_info['port']
            service = port_info.get('service', {})
            
            # Verificar vulnerabilidades conhecidas
            vulns = self._check_service_vulnerabilities(target, port, service)
            vulnerabilities.extend(vulns)
        
        # Verificar certificados SSL se houver HTTPS
        https_ports = [p['port'] for p in port_scan_result['open_ports'] if p['port'] in [443, 8443]]
        for port in https_ports:
            try:
                cert_info = self.ssl_certificate_check(target, port)
                if cert_info.get('warnings'):
                    for warning in cert_info['warnings']:
                        vulnerabilities.append({
                            'type': 'SSL Certificate',
                            'severity': 'Medium',
                            'port': port,
                            'description': warning,
                            'recommendation': 'Renovar certificado SSL'
                        })
            except:
                pass
        
        vuln_result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': self._categorize_vulnerabilities(vulnerabilities)
        }
        
        self.logger.info(f"Scan de vulnerabilidades concluído: {len(vulnerabilities)} vulnerabilidades encontradas")
        
        return vuln_result
    
    def _check_service_vulnerabilities(self, target, port, service):
        """Verifica vulnerabilidades específicas de serviços"""
        vulnerabilities = []
        service_name = service.get('name', '').lower()
        banner = service.get('banner', '')
        
        # Verificações básicas de segurança
        
        # Telnet (inseguro)
        if port == 23 or 'telnet' in service_name:
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'High',
                'port': port,
                'description': 'Telnet é um protocolo inseguro que transmite dados em texto claro',
                'recommendation': 'Substituir por SSH'
            })
        
        # FTP sem criptografia
        if port == 21 or 'ftp' in service_name:
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'Medium',
                'port': port,
                'description': 'FTP transmite credenciais em texto claro',
                'recommendation': 'Usar SFTP ou FTPS'
            })
        
        # HTTP em vez de HTTPS
        if port == 80 or (port != 443 and 'http' in service_name and 'https' not in service_name):
            vulnerabilities.append({
                'type': '	Protocol',
                'severity': 'Medium',
                'port': port,
                'description': 'Tráfego HTTP não criptografado',
                'recommendation': 'Implementar HTTPS'
            })
        
        # Versões antigas conhecidas
        version = service.get('version', '')
        if version:
            old_versions = {
                'apache': ['2.2', '2.0', '1.3'],
                'nginx': ['1.0', '0.8', '0.7'],
                'openssh': ['5.', '4.', '3.'],
                'openssl': ['1.0.1', '1.0.0', '0.9']
            }
            
            for software, old_vers in old_versions.items():
                if software in service_name.lower():
                    for old_ver in old_vers:
                        if old_ver in version:
                            vulnerabilities.append({
                                'type': 'Outdated Software',
                                'severity': 'High',
                                'port': port,
                                'description': f'{software.title()} versão {version} está desatualizada',
                                'recommendation': f'Atualizar {software.title()} para versão mais recente'
                            })
        
        # Verificar banners que revelam informações
        if banner and len(banner) > 50:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'port': port,
                'description': 'Banner do serviço revela informações detalhadas',
                'recommendation': 'Configurar banner mais genérico'
            })
        
        return vulnerabilities
    
    def _categorize_vulnerabilities(self, vulnerabilities):
        """Categoriza vulnerabilidades por severidade"""
        categories = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in categories:
                categories[severity] += 1
        
        return categories
    
    def dns_enumeration(self, domain):
        """Realiza enumeração DNS"""
        self.logger.info(f"Iniciando enumeração DNS para {domain}")
        
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                if platform.system().lower() == 'windows':
                    cmd = ['nslookup', '-type=' + record_type, domain]
                else:
                    cmd = ['dig', '+short', record_type, domain]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    dns_records[record_type] = result.stdout.strip().split('\n')
                    
            except Exception as e:
                dns_records[record_type] = [f"Erro: {e}"]
        
        # Tentar descobrir subdomínios comuns
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog']
        subdomains = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
            except:
                pass
        
        dns_result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'dns_records': dns_records,
            'subdomains_found': subdomains,
            'total_subdomains': len(subdomains)
        }
        
        return dns_result
    
    def run_comprehensive_scan(self, target):
        """Executa scan completo de segurança"""
        self.logger.info(f"Iniciando scan completo de segurança para {target}")
        
        start_time = time.time()
        
        comprehensive_report = {
            'scan_id': str(uuid.uuid4()),
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'port_scan': {},
            'vulnerability_scan': {},
            'ssl_check': {},
            'dns_enumeration': {},
            'network_discovery': {},
            'scan_duration_seconds': 0,
            'summary': {},
            'recommendations': []
        }
        
        try:
            # 1. Scan de portas
            comprehensive_report['port_scan'] = self.port_scan(target)
            
            # 2. Scan de vulnerabilidades
            comprehensive_report['vulnerability_scan'] = self.vulnerability_scan(target)
            
            # 3. Verificação SSL (se aplicável)
            https_ports = [p['port'] for p in comprehensive_report['port_scan']['open_ports'] if p['port'] in [443, 8443]]
            if https_ports:
                comprehensive_report['ssl_check'] = self.ssl_certificate_check(target, https_ports[0])
            
            # 4. Enumeração DNS
            try:
                comprehensive_report['dns_enumeration'] = self.dns_enumeration(target)
            except:
                comprehensive_report['dns_enumeration'] = {'error': 'DNS enumeration failed'}
            
            # 5. Descoberta de rede (se for IP local)
            try:
                if self._is_local_ip(target):
                    network_range = self._get_network_from_ip(target)
                    comprehensive_report['network_discovery'] = self.network_discovery(network_range)
            except:
                pass
            
            # Calcular duração
            comprehensive_report['scan_duration_seconds'] = round(time.time() - start_time, 2)
            
            # Gerar resumo e recomendações
            comprehensive_report['summary'] = self._generate_scan_summary(comprehensive_report)
            comprehensive_report['recommendations'] = self._generate_recommendations(comprehensive_report)
            
        except Exception as e:
            self.logger.error(f"Erro no scan completo: {e}")
            comprehensive_report['error'] = str(e)
        
        self.logger.info(f"Scan completo concluído em {comprehensive_report['scan_duration_seconds']} segundos")
        
        return comprehensive_report
    
    def _is_local_ip(self, ip):
        """Verifica se é um IP local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _get_network_from_ip(self, ip):
        """Obtém a rede a partir de um IP"""
        try:
            parts = ip.split('.')
            parts[3] = '0'
            return '.'.join(parts) + '/24'
        except:
            return '192.168.1.0/24'
    
    def _generate_scan_summary(self, report):
        """Gera resumo do scan"""
        summary = {
            'total_open_ports': len(report.get('port_scan', {}).get('open_ports', [])),
            'total_vulnerabilities': len(report.get('vulnerability_scan', {}).get('vulnerabilities', [])),
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'ssl_issues': 0,
            'risk_level': 'Low'
        }
        
        # Contar vulnerabilidades por severidade
        vulns = report.get('vulnerability_scan', {}).get('vulnerabilities', [])
        for vuln in vulns:
            severity = vuln.get('severity', 'Low')
            if severity == 'Critical':
                summary['critical_vulnerabilities'] += 1
            elif severity == 'High':
                summary['high_vulnerabilities'] += 1
        
        # Verificar problemas SSL
        ssl_check = report.get('ssl_check', {})
        if ssl_check.get('warnings'):
            summary['ssl_issues'] = len(ssl_check['warnings'])
        
        # Determinar nível de risco
        if summary['critical_vulnerabilities'] > 0:
            summary['risk_level'] = 'Critical'
        elif summary['high_vulnerabilities'] > 0:
            summary['risk_level'] = 'High'
        elif summary['total_vulnerabilities'] > 0:
            summary['risk_level'] = 'Medium'
        
        return summary
    
    def _generate_recommendations(self, report):
        """Gera recomendações baseadas no scan"""
        recommendations = []
        
        # Recomendações baseadas em portas abertas
        open_ports = report.get('port_scan', {}).get('open_ports', [])
        if len(open_ports) > 10:
            recommendations.append("Considere fechar portas desnecessárias para reduzir a superfície de ataque")
        
        # Recomendações baseadas em vulnerabilidades
        vulns = report.get('vulnerability_scan', {}).get('vulnerabilities', [])
        if vulns:
            recommendations.append("Corrija as vulnerabilidades identificadas, priorizando as de maior severidade")
        
        # Recomendações SSL
        ssl_check = report.get('ssl_check', {})
        if ssl_check.get('warnings'):
            recommendations.append("Resolva os problemas identificados no certificado SSL")
        
        # Recomendações gerais
        recommendations.extend([
            "Mantenha todos os softwares atualizados",
            "Implemente monitoramento contínuo de segurança",
            "Configure firewalls adequadamente",
            "Realize backups regulares",
            "Implemente autenticação de dois fatores onde possível"
        ])
        
        return recommendations

# Exemplo de uso
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    scanner = SecurityScanner()
    
    print("=== SCAN DE SEGURANÇA ===")
    target = "127.0.0.1"  # Localhost para teste
    
    # Scan completo
    report = scanner.run_comprehensive_scan(target)
    print(json.dumps(report, indent=2, ensure_ascii=False))