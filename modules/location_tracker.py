#!/usr/bin/env python3
"""
Módulo de Localização Geográfica
Sistema de Segurança Cibernética - CyberSec Guardian
"""

import requests
import socket
import json
import logging
from datetime import datetime
import netifaces
import subprocess
import platform

class LocationTracker:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
    def get_public_ip(self):
        """Obtém o IP público do dispositivo"""
        try:
            # Múltiplas fontes para garantir confiabilidade
            services = [
                'https://api.ipify.org?format=json',
                'https://httpbin.org/ip',
                'https://api.myip.com',
                'https://ipinfo.io/json'
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        # Diferentes APIs retornam IP em campos diferentes
                        ip = data.get('ip') or data.get('origin') or data.get('ip_address')
                        if ip:
                            self.logger.info(f"IP público obtido: {ip}")
                            return ip
                except Exception as e:
                    self.logger.warning(f"Falha ao obter IP de {service}: {e}")
                    continue
                    
            # Fallback usando socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return local_ip
                
        except Exception as e:
            self.logger.error(f"Erro ao obter IP público: {e}")
            return None
    
    def get_local_ips(self):
        """Obtém todos os IPs locais do dispositivo"""
        local_ips = []
        try:
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip = addr['addr']
                        if ip != '127.0.0.1':
                            local_ips.append({
                                'interface': interface,
                                'ip': ip,
                                'netmask': addr.get('netmask', ''),
                                'broadcast': addr.get('broadcast', '')
                            })
        except Exception as e:
            self.logger.error(f"Erro ao obter IPs locais: {e}")
            
        return local_ips
    
    def get_geolocation(self, ip=None):
        """Obtém localização geográfica baseada no IP"""
        if not ip:
            ip = self.get_public_ip()
            
        if not ip:
            return None
            
        try:
            # Usando múltiplos serviços de geolocalização
            services = [
                f'http://ip-api.com/json/{ip}',
                f'https://ipinfo.io/{ip}/json',
                f'https://api.ipgeolocation.io/ipgeo?apiKey=free&ip={ip}'
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Normalizar dados de diferentes APIs
                        location = {
                            'ip': ip,
                            'country': data.get('country') or data.get('country_name'),
                            'region': data.get('region') or data.get('regionName') or data.get('state_prov'),
                            'city': data.get('city'),
                            'latitude': data.get('lat') or data.get('latitude'),
                            'longitude': data.get('lon') or data.get('longitude'),
                            'timezone': data.get('timezone'),
                            'isp': data.get('isp') or data.get('org'),
                            'as': data.get('as'),
                            'query_time': datetime.now().isoformat(),
                            'source': service
                        }
                        
                        # Verificar se obtivemos dados válidos
                        if location['country'] and location['city']:
                            self.logger.info(f"Localização obtida: {location['city']}, {location['country']}")
                            return location
                            
                except Exception as e:
                    self.logger.warning(f"Falha ao obter localização de {service}: {e}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Erro ao obter geolocalização: {e}")
            
        return None
    
    def get_network_info(self):
        """Obtém informações detalhadas da rede"""
        network_info = {
            'hostname': socket.gethostname(),
            'fqdn': socket.getfqdn(),
            'local_ips': self.get_local_ips(),
            'public_ip': self.get_public_ip(),
            'default_gateway': None,
            'dns_servers': [],
            'wifi_info': None
        }
        
        try:
            # Obter gateway padrão
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                network_info['default_gateway'] = default_gateway[0]
                
        except Exception as e:
            self.logger.error(f"Erro ao obter gateway: {e}")
        
        try:
            # Obter servidores DNS (Linux/Unix)
            if platform.system() != 'Windows':
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns = line.split()[1]
                            network_info['dns_servers'].append(dns)
        except Exception as e:
            self.logger.warning(f"Não foi possível obter DNS: {e}")
        
        try:
            # Informações WiFi (Linux)
            if platform.system() == 'Linux':
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                if result.returncode == 0:
                    network_info['wifi_info'] = result.stdout
        except Exception as e:
            self.logger.warning(f"Não foi possível obter info WiFi: {e}")
            
        return network_info
    
    def track_location_changes(self, callback=None):
        """Monitora mudanças de localização"""
        current_location = None
        
        while True:
            try:
                new_location = self.get_geolocation()
                
                if new_location and new_location != current_location:
                    self.logger.info("Mudança de localização detectada!")
                    
                    if callback:
                        callback(current_location, new_location)
                    
                    current_location = new_location
                    
                # Aguardar antes da próxima verificação
                import time
                time.sleep(300)  # 5 minutos
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Erro no monitoramento de localização: {e}")
                import time
                time.sleep(60)
    
    def get_full_location_report(self):
        """Gera relatório completo de localização"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'device_info': {
                'hostname': socket.gethostname(),
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release()
            },
            'network_info': self.get_network_info(),
            'geolocation': None,
            'security_notes': []
        }
        
        # Obter geolocalização
        public_ip = report['network_info']['public_ip']
        if public_ip:
            report['geolocation'] = self.get_geolocation(public_ip)
        
        # Adicionar notas de segurança
        if report['geolocation']:
            if 'VPN' in str(report['geolocation'].get('isp', '')):
                report['security_notes'].append("Possível uso de VPN detectado")
            
            if report['geolocation'].get('country') != 'Brazil':
                report['security_notes'].append(f"Localização fora do Brasil: {report['geolocation'].get('country')}")
        
        return report

# Exemplo de uso
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    tracker = LocationTracker()
    
    print("=== RELATÓRIO DE LOCALIZAÇÃO ===")
    report = tracker.get_full_location_report()
    print(json.dumps(report, indent=2, ensure_ascii=False))