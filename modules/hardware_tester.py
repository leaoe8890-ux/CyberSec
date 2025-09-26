#!/usr/bin/env python3
"""
Sistema de Testes de Hardware
Sistema de Segurança Cibernética - CyberSec Guardian
"""

import psutil
import platform
import subprocess
import json
import logging
import time
from datetime import datetime
import threading
import hashlib
import uuid

class HardwareTester:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.alerts = []
        
    def get_system_info(self):
        """Obtém informações básicas do sistema"""
        try:
            uname = platform.uname()
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            
            system_info = {
                'system': uname.system,
                'node_name': uname.node,
                'release': uname.release,
                'version': uname.version,
                'machine': uname.machine,
                'processor': uname.processor,
                'boot_time': boot_time.isoformat(),
                'uptime_seconds': time.time() - psutil.boot_time(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture(),
                'hostname': platform.node(),
                'platform': platform.platform()
            }
            
            return system_info
            
        except Exception as e:
            self.logger.error(f"Erro ao obter informações do sistema: {e}")
            return {}
    
    def test_cpu(self):
        """Testa CPU e obtém informações detalhadas"""
        try:
            # Informações básicas da CPU
            cpu_info = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else None,
                'min_frequency': psutil.cpu_freq().min if psutil.cpu_freq() else None,
                'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else None,
                'cpu_usage_percent': psutil.cpu_percent(interval=1),
                'cpu_usage_per_core': psutil.cpu_percent(interval=1, percpu=True),
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            }
            
            # Teste de stress da CPU
            self.logger.info("Iniciando teste de stress da CPU...")
            start_time = time.time()
            
            # Teste simples de cálculo intensivo
            def cpu_stress_test():
                result = 0
                for i in range(1000000):
                    result += i ** 2
                return result
            
            # Executar teste em múltiplas threads
            threads = []
            for _ in range(psutil.cpu_count()):
                thread = threading.Thread(target=cpu_stress_test)
                threads.append(thread)
                thread.start()
            
            # Monitorar durante o teste
            cpu_usage_during_test = []
            for _ in range(5):  # 5 segundos de teste
                cpu_usage_during_test.append(psutil.cpu_percent(interval=1))
            
            # Aguardar threads terminarem
            for thread in threads:
                thread.join()
            
            end_time = time.time()
            
            cpu_info.update({
                'stress_test_duration': end_time - start_time,
                'cpu_usage_during_stress': cpu_usage_during_test,
                'average_usage_during_stress': sum(cpu_usage_during_test) / len(cpu_usage_during_test),
                'max_usage_during_stress': max(cpu_usage_during_test)
            })
            
            # Verificar temperaturas (se disponível)
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    cpu_info['temperatures'] = temps
            except:
                cpu_info['temperatures'] = "Não disponível"
            
            return cpu_info
            
        except Exception as e:
            self.logger.error(f"Erro no teste de CPU: {e}")
            return {}
    
    def test_memory(self):
        """Testa memória RAM"""
        try:
            # Informações básicas da memória
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            memory_info = {
                'total_ram_gb': round(memory.total / (1024**3), 2),
                'available_ram_gb': round(memory.available / (1024**3), 2),
                'used_ram_gb': round(memory.used / (1024**3), 2),
                'ram_usage_percent': memory.percent,
                'total_swap_gb': round(swap.total / (1024**3), 2),
                'used_swap_gb': round(swap.used / (1024**3), 2),
                'swap_usage_percent': swap.percent,
                'memory_info': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'free': memory.free,
                    'active': getattr(memory, 'active', 0),
                    'inactive': getattr(memory, 'inactive', 0),
                    'buffers': getattr(memory, 'buffers', 0),
                    'cached': getattr(memory, 'cached', 0),
                    'shared': getattr(memory, 'shared', 0)
                }
            }
            
            # Teste de alocação de memória
            self.logger.info("Iniciando teste de memória...")
            
            # Alocar blocos de memória para teste
            test_data = []
            allocated_mb = 0
            max_allocation = min(1024, int(memory.available / (1024**2) * 0.1))  # Máximo 10% da memória disponível
            
            try:
                for i in range(max_allocation):
                    # Alocar 1MB de dados
                    data = bytearray(1024 * 1024)  # 1MB
                    test_data.append(data)
                    allocated_mb += 1
                    
                    # Verificar uso de memória a cada 100MB
                    if allocated_mb % 100 == 0:
                        current_memory = psutil.virtual_memory()
                        if current_memory.percent > 90:  # Parar se uso > 90%
                            break
                
                memory_info['memory_test'] = {
                    'allocated_mb': allocated_mb,
                    'test_successful': True,
                    'final_memory_usage': psutil.virtual_memory().percent
                }
                
            except MemoryError:
                memory_info['memory_test'] = {
                    'allocated_mb': allocated_mb,
                    'test_successful': False,
                    'error': 'MemoryError - Memória insuficiente'
                }
            
            # Limpar dados de teste
            del test_data
            
            return memory_info
            
        except Exception as e:
            self.logger.error(f"Erro no teste de memória: {e}")
            return {}
    
    def test_disk(self):
        """Testa discos e armazenamento"""
        try:
            disk_info = {
                'partitions': [],
                'disk_io': psutil.disk_io_counters(perdisk=True) if psutil.disk_io_counters() else {},
                'total_disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {}
            }
            
            # Informações das partições
            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    partition_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'file_system': partition.fstype,
                        'total_gb': round(partition_usage.total / (1024**3), 2),
                        'used_gb': round(partition_usage.used / (1024**3), 2),
                        'free_gb': round(partition_usage.free / (1024**3), 2),
                        'usage_percent': round((partition_usage.used / partition_usage.total) * 100, 2)
                    }
                    disk_info['partitions'].append(partition_info)
                except PermissionError:
                    # Algumas partições podem não ser acessíveis
                    continue
            
            # Teste de velocidade de escrita/leitura
            self.logger.info("Iniciando teste de velocidade do disco...")
            
            try:
                import tempfile
                import os
                
                test_file = tempfile.NamedTemporaryFile(delete=False)
                test_data = b'0' * (1024 * 1024)  # 1MB de dados
                
                # Teste de escrita
                start_time = time.time()
                for _ in range(10):  # Escrever 10MB
                    test_file.write(test_data)
                test_file.flush()
                os.fsync(test_file.fileno())
                write_time = time.time() - start_time
                
                test_file.close()
                
                # Teste de leitura
                start_time = time.time()
                with open(test_file.name, 'rb') as f:
                    while f.read(1024 * 1024):  # Ler em blocos de 1MB
                        pass
                read_time = time.time() - start_time
                
                # Limpar arquivo de teste
                os.unlink(test_file.name)
                
                disk_info['speed_test'] = {
                    'write_speed_mbps': round(10 / write_time, 2),
                    'read_speed_mbps': round(10 / read_time, 2),
                    'write_time_seconds': round(write_time, 2),
                    'read_time_seconds': round(read_time, 2)
                }
                
            except Exception as e:
                disk_info['speed_test'] = {'error': str(e)}
            
            return disk_info
            
        except Exception as e:
            self.logger.error(f"Erro no teste de disco: {e}")
            return {}
    
    def test_network_interfaces(self):
        """Testa interfaces de rede"""
        try:
            network_info = {
                'interfaces': {},
                'network_io': psutil.net_io_counters(pernic=True),
                'total_network_io': psutil.net_io_counters()._asdict(),
                'connections': len(psutil.net_connections()),
                'network_stats': {}
            }
            
            # Informações das interfaces
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for interface_name, addresses in interfaces.items():
                interface_info = {
                    'addresses': [],
                    'stats': stats.get(interface_name)._asdict() if interface_name in stats else {}
                }
                
                for addr in addresses:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_info['addresses'].append(addr_info)
                
                network_info['interfaces'][interface_name] = interface_info
            
            # Teste de conectividade
            self.logger.info("Testando conectividade de rede...")
            
            test_hosts = ['8.8.8.8', '1.1.1.1', 'google.com']
            connectivity_results = {}
            
            for host in test_hosts:
                try:
                    if platform.system().lower() == 'windows':
                        cmd = ['ping', '-n', '3', host]
                    else:
                        cmd = ['ping', '-c', '3', host]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    connectivity_results[host] = {
                        'success': result.returncode == 0,
                        'output': result.stdout if result.returncode == 0 else result.stderr
                    }
                except Exception as e:
                    connectivity_results[host] = {
                        'success': False,
                        'error': str(e)
                    }
            
            network_info['connectivity_test'] = connectivity_results
            
            return network_info
            
        except Exception as e:
            self.logger.error(f"Erro no teste de rede: {e}")
            return {}
    
    def get_hardware_sensors(self):
        """Obtém dados dos sensores de hardware"""
        try:
            sensors_info = {
                'temperatures': {},
                'fans': {},
                'battery': None
            }
            
            # Temperaturas
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        sensors_info['temperatures'][name] = []
                        for entry in entries:
                            temp_info = {
                                'label': entry.label or name,
                                'current': entry.current,
                                'high': entry.high,
                                'critical': entry.critical
                            }
                            sensors_info['temperatures'][name].append(temp_info)
            except:
                sensors_info['temperatures'] = "Não disponível"
            
            # Ventiladores
            try:
                fans = psutil.sensors_fans()
                if fans:
                    for name, entries in fans.items():
                        sensors_info['fans'][name] = []
                        for entry in entries:
                            fan_info = {
                                'label': entry.label or name,
                                'current': entry.current
                            }
                            sensors_info['fans'][name].append(fan_info)
            except:
                sensors_info['fans'] = "Não disponível"
            
            # Bateria
            try:
                battery = psutil.sensors_battery()
                if battery:
                    sensors_info['battery'] = {
                        'percent': battery.percent,
                        'seconds_left': battery.secsleft,
                        'power_plugged': battery.power_plugged
                    }
            except:
                sensors_info['battery'] = "Não disponível"
            
            return sensors_info
            
        except Exception as e:
            self.logger.error(f"Erro ao obter sensores: {e}")
            return {}
    
    def generate_hardware_fingerprint(self):
        """Gera uma impressão digital única do hardware"""
        try:
            # Coletar informações únicas do hardware
            system_info = self.get_system_info()
            cpu_info = psutil.cpu_count(logical=False), psutil.cpu_count(logical=True)
            memory_info = psutil.virtual_memory().total
            disk_info = []
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append((partition.device, usage.total))
                except:
                    continue
            
            # Criar string única
            fingerprint_data = f"{system_info.get('machine', '')}-{cpu_info}-{memory_info}-{sorted(disk_info)}"
            
            # Gerar hash
            fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
            
            return {
                'fingerprint': fingerprint,
                'components': {
                    'machine': system_info.get('machine', ''),
                    'cpu_cores': cpu_info,
                    'total_memory': memory_info,
                    'disks': disk_info
                },
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar fingerprint: {e}")
            return {}
    
    def run_full_hardware_test(self):
        """Executa teste completo de hardware"""
        self.logger.info("Iniciando teste completo de hardware...")
        
        start_time = time.time()
        
        report = {
            'test_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'system_info': self.get_system_info(),
            'cpu_test': self.test_cpu(),
            'memory_test': self.test_memory(),
            'disk_test': self.test_disk(),
            'network_test': self.test_network_interfaces(),
            'sensors': self.get_hardware_sensors(),
            'hardware_fingerprint': self.generate_hardware_fingerprint(),
            'test_duration_seconds': 0,
            'alerts': [],
            'overall_health': 'UNKNOWN'
        }
        
        # Calcular duração do teste
        report['test_duration_seconds'] = round(time.time() - start_time, 2)
        
        # Analisar resultados e gerar alertas
        self._analyze_results(report)
        
        self.logger.info(f"Teste de hardware concluído em {report['test_duration_seconds']} segundos")
        
        return report
    
    def _analyze_results(self, report):
        """Analisa resultados e gera alertas"""
        alerts = []
        health_score = 100
        
        # Analisar CPU
        cpu_test = report.get('cpu_test', {})
        if cpu_test.get('cpu_usage_percent', 0) > 90:
            alerts.append("ALERTA: Uso de CPU muito alto (>90%)")
            health_score -= 20
        
        if cpu_test.get('max_usage_during_stress', 0) < 50:
            alerts.append("AVISO: CPU pode estar com problemas de desempenho")
            health_score -= 10
        
        # Analisar Memória
        memory_test = report.get('memory_test', {})
        if memory_test.get('ram_usage_percent', 0) > 85:
            alerts.append("ALERTA: Uso de memória RAM muito alto (>85%)")
            health_score -= 15
        
        if memory_test.get('swap_usage_percent', 0) > 50:
            alerts.append("AVISO: Uso de swap elevado (>50%)")
            health_score -= 10
        
        # Analisar Disco
        disk_test = report.get('disk_test', {})
        for partition in disk_test.get('partitions', []):
            if partition.get('usage_percent', 0) > 90:
                alerts.append(f"ALERTA: Disco {partition['device']} quase cheio ({partition['usage_percent']}%)")
                health_score -= 15
        
        # Analisar Temperaturas
        sensors = report.get('sensors', {})
        temps = sensors.get('temperatures', {})
        if isinstance(temps, dict):
            for sensor_name, temp_list in temps.items():
                for temp in temp_list:
                    if temp.get('current', 0) > 80:
                        alerts.append(f"ALERTA: Temperatura alta em {sensor_name}: {temp['current']}°C")
                        health_score -= 20
        
        # Determinar saúde geral
        if health_score >= 90:
            overall_health = "EXCELENTE"
        elif health_score >= 75:
            overall_health = "BOM"
        elif health_score >= 60:
            overall_health = "REGULAR"
        elif health_score >= 40:
            overall_health = "RUIM"
        else:
            overall_health = "CRÍTICO"
        
        report['alerts'] = alerts
        report['health_score'] = health_score
        report['overall_health'] = overall_health

# Exemplo de uso
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    tester = HardwareTester()
    
    print("=== TESTE COMPLETO DE HARDWARE ===")
    report = tester.run_full_hardware_test()
    print(json.dumps(report, indent=2, ensure_ascii=False))