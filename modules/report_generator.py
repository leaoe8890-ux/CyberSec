#!/usr/bin/env python3
"""
Módulo de Geração de Relatórios
Sistema de Segurança Cibernética - CyberSec Guardian
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
import uuid
import base64

class ReportGenerator:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
    def generate_html_report(self, report_data, report_type="comprehensive"):
        """Gera relatório em formato HTML"""
        try:
            html_content = self._create_html_template(report_data, report_type)
            
            # Salvar arquivo HTML
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_report_{timestamp}.html"
            filepath = reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Relatório HTML gerado: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório HTML: {e}")
            return None
    
    def _create_html_template(self, report_data, report_type):
        """Cria template HTML para o relatório"""
        
        # CSS para estilização
        css_styles = """
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            
            .header {
                background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            
            .header h1 {
                font-size: 2.5em;
                margin-bottom: 10px;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }
            
            .header .subtitle {
                font-size: 1.2em;
                opacity: 0.9;
            }
            
            .content {
                padding: 30px;
            }
            
            .section {
                margin-bottom: 30px;
                background: #f8f9fa;
                border-radius: 10px;
                padding: 25px;
                border-left: 5px solid #3498db;
            }
            
            .section h2 {
                color: #2c3e50;
                margin-bottom: 20px;
                font-size: 1.8em;
                display: flex;
                align-items: center;
            }
            
            .section h2 .emoji {
                margin-right: 10px;
                font-size: 1.2em;
            }
            
            .info-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }
            
            .info-card {
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                border-left: 4px solid #3498db;
            }
            
            .info-card h3 {
                color: #2c3e50;
                margin-bottom: 15px;
                font-size: 1.3em;
            }
            
            .info-item {
                display: flex;
                justify-content: space-between;
                margin-bottom: 10px;
                padding: 8px 0;
                border-bottom: 1px solid #ecf0f1;
            }
            
            .info-item:last-child {
                border-bottom: none;
            }
            
            .info-label {
                font-weight: 600;
                color: #555;
            }
            
            .info-value {
                color: #2c3e50;
                font-weight: 500;
            }
            
            .status-badge {
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.9em;
                font-weight: 600;
                text-transform: uppercase;
            }
            
            .status-excellent { background: #d4edda; color: #155724; }
            .status-good { background: #fff3cd; color: #856404; }
            .status-warning { background: #f8d7da; color: #721c24; }
            .status-critical { background: #f5c6cb; color: #721c24; }
            
            .risk-low { background: #d4edda; color: #155724; }
            .risk-medium { background: #fff3cd; color: #856404; }
            .risk-high { background: #f8d7da; color: #721c24; }
            .risk-critical { background: #f5c6cb; color: #721c24; }
            
            .alerts-list {
                background: #fff5f5;
                border: 1px solid #fed7d7;
                border-radius: 8px;
                padding: 15px;
                margin-top: 15px;
            }
            
            .alert-item {
                padding: 10px;
                margin-bottom: 10px;
                background: white;
                border-radius: 5px;
                border-left: 4px solid #e53e3e;
            }
            
            .alert-item:last-child {
                margin-bottom: 0;
            }
            
            .recommendations {
                background: #f0fff4;
                border: 1px solid #9ae6b4;
                border-radius: 8px;
                padding: 20px;
                margin-top: 20px;
            }
            
            .recommendation-item {
                padding: 10px;
                margin-bottom: 10px;
                background: white;
                border-radius: 5px;
                border-left: 4px solid #38a169;
                display: flex;
                align-items: center;
            }
            
            .recommendation-item:last-child {
                margin-bottom: 0;
            }
            
            .ports-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            
            .ports-table th,
            .ports-table td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ecf0f1;
            }
            
            .ports-table th {
                background: #3498db;
                color: white;
                font-weight: 600;
            }
            
            .ports-table tr:hover {
                background: #f8f9fa;
            }
            
            .footer {
                background: #2c3e50;
                color: white;
                text-align: center;
                padding: 20px;
                font-size: 0.9em;
            }
            
            .timestamp {
                color: #7f8c8d;
                font-size: 0.9em;
                margin-top: 10px;
            }
            
            @media (max-width: 768px) {
                .info-grid {
                    grid-template-columns: 1fr;
                }
                
                .header h1 {
                    font-size: 2em;
                }
                
                .content {
                    padding: 20px;
                }
            }
        </style>
        """
        
        # Gerar conteúdo baseado no tipo de relatório
        if report_type == "comprehensive":
            content = self._generate_comprehensive_content(report_data)
        elif report_type == "hardware":
            content = self._generate_hardware_content(report_data)
        elif report_type == "security":
            content = self._generate_security_content(report_data)
        elif report_type == "location":
            content = self._generate_location_content(report_data)
        else:
            content = self._generate_generic_content(report_data)
        
        # Template HTML completo
        html_template = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>CyberSec Guardian - Relatório {report_type.title()}</title>
            {css_styles}
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ CyberSec Guardian</h1>
                    <div class="subtitle">Relatório de Segurança Cibernética - {report_type.title()}</div>
                    <div class="timestamp">Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}</div>
                </div>
                
                <div class="content">
                    {content}
                </div>
                
                <div class="footer">
                    <p>© 2024 CyberSec Guardian - Sistema de Segurança Cibernética</p>
                    <p>Relatório gerado automaticamente pelo sistema</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_template
    
    def _generate_comprehensive_content(self, report_data):
        """Gera conteúdo para relatório completo"""
        content = ""
        
        # Resumo Executivo
        summary = report_data.get('summary', {})
        risk_level = summary.get('risk_level', 'Unknown')
        risk_class = f"risk-{risk_level.lower()}"
        
        content += f"""
        <div class="section">
            <h2><span class="emoji">📊</span>Resumo Executivo</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Status Geral</h3>
                    <div class="info-item">
                        <span class="info-label">Nível de Risco:</span>
                        <span class="status-badge {risk_class}">{risk_level}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Total de Problemas:</span>
                        <span class="info-value">{summary.get('total_issues', 0)}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Problemas Críticos:</span>
                        <span class="info-value">{summary.get('critical_issues', 0)}</span>
                    </div>
                </div>
                
                <div class="info-card">
                    <h3>Status por Módulo</h3>
                    <div class="info-item">
                        <span class="info-label">Hardware:</span>
                        <span class="info-value">{summary.get('hardware_health', 'Unknown')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Segurança:</span>
                        <span class="info-value">{summary.get('security_risk', 'Unknown')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Localização:</span>
                        <span class="info-value">{summary.get('location_alerts', 0)} alertas</span>
                    </div>
                </div>
            </div>
        </div>
        """
        
        # Relatório de Hardware
        hardware_report = report_data.get('hardware_report', {})
        if hardware_report:
            content += self._generate_hardware_section(hardware_report)
        
        # Relatório de Segurança
        security_report = report_data.get('security_report', {})
        if security_report:
            content += self._generate_security_section(security_report)
        
        # Relatório de Localização
        location_report = report_data.get('location_report', {})
        if location_report:
            content += self._generate_location_section(location_report)
        
        # Recomendações
        recommendations = report_data.get('recommendations', [])
        if recommendations:
            content += f"""
            <div class="section">
                <h2><span class="emoji">💡</span>Recomendações</h2>
                <div class="recommendations">
                    {''.join([f'<div class="recommendation-item">{rec}</div>' for rec in recommendations[:10]])}
                </div>
            </div>
            """
        
        return content
    
    def _generate_hardware_section(self, hardware_report):
        """Gera seção de hardware"""
        system_info = hardware_report.get('system_info', {})
        cpu_test = hardware_report.get('cpu_test', {})
        memory_test = hardware_report.get('memory_test', {})
        disk_test = hardware_report.get('disk_test', {})
        
        health = hardware_report.get('overall_health', 'Unknown')
        health_class = {
            'EXCELENTE': 'status-excellent',
            'BOM': 'status-good',
            'REGULAR': 'status-warning',
            'RUIM': 'status-critical',
            'CRÍTICO': 'status-critical'
        }.get(health, 'status-warning')
        
        content = f"""
        <div class="section">
            <h2><span class="emoji">🖥️</span>Relatório de Hardware</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Sistema</h3>
                    <div class="info-item">
                        <span class="info-label">Hostname:</span>
                        <span class="info-value">{system_info.get('hostname', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Sistema:</span>
                        <span class="info-value">{system_info.get('system', 'N/A')} {system_info.get('release', '')}</span>
                    </div>
                    <div class="info-item">
                        
                        <span class="info-label">Saúde Geral:</span>
                        <span class="status-badge {health_class}">{health}</span>
                    </div>
                </div>
                
                <div class="info-card">
                    <h3>CPU</h3>
                    <div class="info-item">
                        <span class="info-label">Cores Físicos:</span>
                        <span class="info-value">{cpu_test.get('physical_cores', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Cores Lógicos:</span>
                        <span class="info-value">{cpu_test.get('total_cores', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Uso Atual:</span>
                        <span class="info-value">{cpu_test.get('cpu_usage_percent', 'N/A')}%</span>
                    </div>
                </div>
                
                <div class="info-card">
                    <h3>Memória</h3>
                    <div class="info-item">
                        <span class="info-label">RAM Total:</span>
                        <span class="info-value">{memory_test.get('total_ram_gb', 'N/A')} GB</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">RAM Disponível:</span>
                        <span class="info-value">{memory_test.get('available_ram_gb', 'N/A')} GB</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Uso de RAM:</span>
                        <span class="info-value">{memory_test.get('ram_usage_percent', 'N/A')}%</span>
                    </div>
                </div>
            </div>
        """
        
        # Alertas de hardware
        alerts = hardware_report.get('alerts', [])
        if alerts:
            content += f"""
            <div class="alerts-list">
                <h3>⚠️ Alertas de Hardware</h3>
                {''.join([f'<div class="alert-item">{alert}</div>' for alert in alerts])}
            </div>
            """
        
        content += "</div>"
        return content
    
    def _generate_security_section(self, security_report):
        """Gera seção de segurança"""
        summary = security_report.get('summary', {})
        port_scan = security_report.get('port_scan', {})
        vuln_scan = security_report.get('vulnerability_scan', {})
        
        risk_level = summary.get('risk_level', 'Unknown')
        risk_class = f"risk-{risk_level.lower()}"
        
        content = f"""
        <div class="section">
            <h2><span class="emoji">🔒</span>Relatório de Segurança</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Resumo de Segurança</h3>
                    <div class="info-item">
                        <span class="info-label">Nível de Risco:</span>
                        <span class="status-badge {risk_class}">{risk_level}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Portas Abertas:</span>
                        <span class="info-value">{summary.get('total_open_ports', 0)}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Vulnerabilidades:</span>
                        <span class="info-value">{summary.get('total_vulnerabilities', 0)}</span>
                    </div>
                </div>
                
                <div class="info-card">
                    <h3>Vulnerabilidades por Severidade</h3>
                    <div class="info-item">
                        <span class="info-label">Críticas:</span>
                        <span class="info-value">{summary.get('critical_vulnerabilities', 0)}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Altas:</span>
                        <span class="info-value">{summary.get('high_vulnerabilities', 0)}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Problemas SSL:</span>
                        <span class="info-value">{summary.get('ssl_issues', 0)}</span>
                    </div>
                </div>
            </div>
        """
        
        # Portas abertas
        open_ports = port_scan.get('open_ports', [])
        if open_ports:
            content += """
            <h3>🔓 Portas Abertas</h3>
            <table class="ports-table">
                <thead>
                    <tr>
                        <th>Porta</th>
                        <th>Protocolo</th>
                        <th>Serviço</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for port in open_ports[:20]:  # Mostrar apenas as 20 primeiras
                service = port.get('service', {}).get('name', 'Unknown')
                content += f"""
                    <tr>
                        <td>{port.get('port', 'N/A')}</td>
                        <td>TCP</td>
                        <td>{service}</td>
                        <td>{port.get('state', 'N/A')}</td>
                    </tr>
                """
            
            content += "</tbody></table>"
        
        # Vulnerabilidades
        vulnerabilities = vuln_scan.get('vulnerabilities', [])
        if vulnerabilities:
            content += f"""
            <div class="alerts-list">
                <h3>⚠️ Vulnerabilidades Identificadas</h3>
                {''.join([f'<div class="alert-item"><strong>{vuln.get("type", "Unknown")}</strong> - Porta {vuln.get("port", "N/A")} - {vuln.get("description", "N/A")}</div>' for vuln in vulnerabilities[:10]])}
            </div>
            """
        
        content += "</div>"
        return content
    
    def _generate_location_section(self, location_report):
        """Gera seção de localização"""
        device_info = location_report.get('device_info', {})
        network_info = location_report.get('network_info', {})
        geolocation = location_report.get('geolocation', {})
        
        content = f"""
        <div class="section">
            <h2><span class="emoji">📍</span>Relatório de Localização</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Informações do Dispositivo</h3>
                    <div class="info-item">
                        <span class="info-label">Hostname:</span>
                        <span class="info-value">{device_info.get('hostname', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Sistema:</span>
                        <span class="info-value">{device_info.get('system', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Plataforma:</span>
                        <span class="info-value">{device_info.get('platform', 'N/A')}</span>
                    </div>
                </div>
                
                <div class="info-card">
                    <h3>Informações de Rede</h3>
                    <div class="info-item">
                        <span class="info-label">IP Público:</span>
                        <span class="info-value">{network_info.get('public_ip', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Gateway:</span>
                        <span class="info-value">{network_info.get('default_gateway', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">FQDN:</span>
                        <span class="info-value">{network_info.get('fqdn', 'N/A')}</span>
                    </div>
                </div>
        """
        
        if geolocation:
            content += f"""
                <div class="info-card">
                    <h3>Geolocalização</h3>
                    <div class="info-item">
                        <span class="info-label">País:</span>
                        <span class="info-value">{geolocation.get('country', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Cidade:</span>
                        <span class="info-value">{geolocation.get('city', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">ISP:</span>
                        <span class="info-value">{geolocation.get('isp', 'N/A')}</span>
                    </div>
                </div>
            """
        
        content += "</div>"
        
        # Alertas de localização
        security_notes = location_report.get('security_notes', [])
        if security_notes:
            content += f"""
            <div class="alerts-list">
                <h3>⚠️ Alertas de Localização</h3>
                {''.join([f'<div class="alert-item">{note}</div>' for note in security_notes])}
            </div>
            """
        
        content += "</div>"
        return content
    
    def _generate_hardware_content(self, report_data):
        """Gera conteúdo específico para relatório de hardware"""
        return self._generate_hardware_section(report_data)
    
    def _generate_security_content(self, report_data):
        """Gera conteúdo específico para relatório de segurança"""
        return self._generate_security_section(report_data)
    
    def _generate_location_content(self, report_data):
        """Gera conteúdo específico para relatório de localização"""
        return self._generate_location_section(report_data)
    
    def _generate_generic_content(self, report_data):
        """Gera conteúdo genérico para qualquer tipo de relatório"""
        content = f"""
        <div class="section">
            <h2><span class="emoji">📋</span>Dados do Relatório</h2>
            <div class="info-card">
                <pre style="background: #f8f9fa; padding: 20px; border-radius: 8px; overflow-x: auto;">
{json.dumps(report_data, indent=2, ensure_ascii=False, default=str)}
                </pre>
            </div>
        </div>
        """
        return content
    
    def generate_pdf_report(self, report_data, report_type="comprehensive"):
        """Gera relatório em formato PDF (requer wkhtmltopdf)"""
        try:
            # Primeiro gerar HTML
            html_file = self.generate_html_report(report_data, report_type)
            if not html_file:
                return None
            
            # Converter HTML para PDF usando wkhtmltopdf
            pdf_file = html_file.replace('.html', '.pdf')
            
            cmd = [
                'wkhtmltopdf',
                '--page-size', 'A4',
                '--margin-top', '0.75in',
                '--margin-right', '0.75in',
                '--margin-bottom', '0.75in',
                '--margin-left', '0.75in',
                '--encoding', 'UTF-8',
                '--no-outline',
                html_file,
                pdf_file
            ]
            
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"Relatório PDF gerado: {pdf_file}")
                return pdf_file
            else:
                self.logger.error(f"Erro ao gerar PDF: {result.stderr}")
                return html_file  # Retornar HTML se PDF falhar
                
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório PDF: {e}")
            return None
    
    def generate_json_report(self, report_data, report_type="comprehensive"):
        """Gera relatório em formato JSON"""
        try:
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_report_{timestamp}.json"
            filepath = reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            self.logger.info(f"Relatório JSON gerado: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório JSON: {e}")
            return None
    
    def generate_csv_report(self, report_data, report_type="comprehensive"):
        """Gera relatório em formato CSV (dados tabulares)"""
        try:
            import csv
            
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_report_{timestamp}.csv"
            filepath = reports_dir / filename
            
            # Extrair dados tabulares baseado no tipo de relatório
            if report_type == "security":
                self._generate_security_csv(report_data, filepath)
            elif report_type == "hardware":
                self._generate_hardware_csv(report_data, filepath)
            else:
                self._generate_generic_csv(report_data, filepath)
            
            self.logger.info(f"Relatório CSV gerado: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório CSV: {e}")
            return None
    
    def _generate_security_csv(self, report_data, filepath):
        """Gera CSV específico para dados de segurança"""
        import csv
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Cabeçalho
            writer.writerow(['Tipo', 'Porta', 'Serviço', 'Severidade', 'Descrição', 'Recomendação'])
            
            # Portas abertas
            port_scan = report_data.get('port_scan', {})
            for port in port_scan.get('open_ports', []):
                service = port.get('service', {}).get('name', 'Unknown')
                writer.writerow(['Porta Aberta', port.get('port'), service, 'Info', f"Porta {port.get('port')} aberta", 'Verificar necessidade'])
            
            # Vulnerabilidades
            vuln_scan = report_data.get('vulnerability_scan', {})
            for vuln in vuln_scan.get('vulnerabilities', []):
                writer.writerow([
                    'Vulnerabilidade',
                    vuln.get('port', 'N/A'),
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('description', 'N/A'),
                    vuln.get('recommendation', 'N/A')
                ])
    
    def _generate_hardware_csv(self, report_data, filepath):
        """Gera CSV específico para dados de hardware"""
        import csv
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Cabeçalho
            writer.writerow(['Componente', 'Métrica', 'Valor', 'Unidade', 'Status'])
            
            # CPU
            cpu_test = report_data.get('cpu_test', {})
            writer.writerow(['CPU', 'Cores Físicos', cpu_test.get('physical_cores', 'N/A'), 'unidades', 'OK'])
            writer.writerow(['CPU', 'Cores Lógicos', cpu_test.get('total_cores', 'N/A'), 'unidades', 'OK'])
            writer.writerow(['CPU', 'Uso Atual', cpu_test.get('cpu_usage_percent', 'N/A'), '%', 'OK'])
            
            # Memória
            memory_test = report_data.get('memory_test', {})
            writer.writerow(['Memória', 'RAM Total', memory_test.get('total_ram_gb', 'N/A'), 'GB', 'OK'])
            writer.writerow(['Memória', 'RAM Usada', memory_test.get('used_ram_gb', 'N/A'), 'GB', 'OK'])
            writer.writerow(['Memória', 'Uso RAM', memory_test.get('ram_usage_percent', 'N/A'), '%', 'OK'])
            
            # Discos
            disk_test = report_data.get('disk_test', {})
            for partition in disk_test.get('partitions', []):
                writer.writerow([
                    'Disco',
                    f"Uso {partition.get('device', 'N/A')}",
                    partition.get('usage_percent', 'N/A'),
                    '%',
                    'OK' if partition.get('usage_percent', 0) < 90 else 'Alerta'
                ])
    
    def _generate_generic_csv(self, report_data, filepath):
        """Gera CSV genérico para qualquer tipo de dados"""
        import csv
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Cabeçalho
            writer.writerow(['Chave', 'Valor'])
            
            # Função recursiva para extrair dados
            def extract_data(data, prefix=''):
                for key, value in data.items():
                    if isinstance(value, dict):
                        extract_data(value, f"{prefix}{key}.")
                    elif isinstance(value, list):
                        for i, item in enumerate(value):
                            if isinstance(item, dict):
                                extract_data(item, f"{prefix}{key}[{i}].")
                            else:
                                writer.writerow([f"{prefix}{key}[{i}]", str(item)])
                    else:
                        writer.writerow([f"{prefix}{key}", str(value)])
            
            extract_data(report_data)

# Exemplo de uso
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Dados de exemplo
    sample_data = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'risk_level': 'Medium',
            'total_issues': 5,
            'critical_issues': 1
        },
        'hardware_report': {
            'overall_health': 'BOM',
            'alerts': ['Uso de memória alto'],
            'system_info': {'hostname': 'test-server', 'system': 'Linux'},
            'cpu_test': {'physical_cores': 4, 'total_cores': 8, 'cpu_usage_percent': 25.5},
            'memory_test': {'total_ram_gb': 16, 'ram_usage_percent': 75.2}
        }
    }
    
    generator = ReportGenerator()
    
    print("=== GERADOR DE RELATÓRIOS ===")
    html_file = generator.generate_html_report(sample_data, "comprehensive")
    print(f"Relatório HTML: {html_file}")
    
    json_file = generator.generate_json_report(sample_data, "comprehensive")
    print(f"Relatório JSON: {json_file}")