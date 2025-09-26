#!/usr/bin/env python3
"""
Módulo de Envio de Mensagens
Sistema de Segurança Cibernética - CyberSec Guardian
"""

import smtplib
import json
import logging
import requests
import socket
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
import threading
import time

class MessageSender:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.message_queue = []
        self.sending_thread = None
        self.is_running = False
        
    def send_email(self, subject, message, attachments=None, recipient=None):
        """Envia email com alertas de segurança"""
        try:
            # Configurações do email
            smtp_server = self.config.get('messaging', {}).get('smtp_server', 'smtp.gmail.com')
            smtp_port = self.config.get('messaging', {}).get('smtp_port', 587)
            email_from = self.config.get('messaging', {}).get('email_from', 'security@company.com')
            email_to = recipient or self.config.get('messaging', {}).get('email_to', 'admin@company.com')
            email_password = self.config.get('messaging', {}).get('email_password', '')
            
            if not email_password:
                self.logger.warning("Senha do email não configurada")
                return False
            
            # Criar mensagem
            msg = MIMEMultipart()
            msg['From'] = email_from
            msg['To'] = email_to
            msg['Subject'] = f"[CyberSec Guardian] {subject}"
            
            # Corpo da mensagem
            body = f"""
ALERTA DE SEGURANÇA - CyberSec Guardian
=====================================

Timestamp: {datetime.now().isoformat()}
Hostname: {socket.gethostname()}

{message}

=====================================
Este é um alerta automático do sistema de segurança.
Não responda a este email.
            """
            
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Anexos
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= {os.path.basename(file_path)}'
                            )
                            msg.attach(part)
            
            # Enviar email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(email_from, email_password)
            text = msg.as_string()
            server.sendmail(email_from, email_to, text)
            server.quit()
            
            self.logger.info(f"Email enviado com sucesso para {email_to}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar email: {e}")
            return False
    
    def send_telegram_message(self, message, chat_id=None):
        """Envia mensagem via Telegram Bot"""
        try:
            bot_token = self.config.get('messaging', {}).get('telegram_bot_token', '')
            chat_id = chat_id or self.config.get('messaging', {}).get('telegram_chat_id', '')
            
            if not bot_token or not chat_id:
                self.logger.warning("Token do Telegram ou Chat ID não configurados")
                return False
            
            # Formatar mensagem
            formatted_message = f"""
🚨 *ALERTA DE SEGURANÇA*
🤖 CyberSec Guardian

📅 *Data:* {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
🖥️ *Host:* {socket.gethostname()}

📝 *Mensagem:*
{message}

⚠️ _Alerta automático do sistema de segurança_
            """
            
            # URL da API do Telegram
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            
            # Dados da requisição
            data = {
                'chat_id': chat_id,
                'text': formatted_message,
                'parse_mode': 'Markdown'
            }
            
            # Enviar mensagem
            response = requests.post(url, data=data, timeout=10)
            
            if response.status_code == 200:
                self.logger.info("Mensagem Telegram enviada com sucesso")
                return True
            else:
                self.logger.error(f"Erro ao enviar Telegram: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao enviar mensagem Telegram: {e}")
            return False
    
    def send_webhook_notification(self, webhook_url, data):
        """Envia notificação via webhook"""
        try:
            # Preparar dados
            payload = {
                'timestamp': datetime.now().isoformat(),
                'hostname': socket.gethostname(),
                'source': 'CyberSec Guardian',
                'data': data
            }
            
            # Enviar requisição
            response = requests.post(
                webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 201, 202]:
                self.logger.info("Webhook enviado com sucesso")
                return True
            else:
                self.logger.error(f"Erro no webhook: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao enviar webhook: {e}")
            return False
    
    def send_slack_message(self, message, webhook_url=None):
        """Envia mensagem para Slack"""
        try:
            webhook_url = webhook_url or self.config.get('messaging', {}).get('slack_webhook', '')
            
            if not webhook_url:
                self.logger.warning("Webhook do Slack não configurado")
                return False
            
            # Formatar mensagem para Slack
            payload = {
                "text": "🚨 Alerta de Segurança - CyberSec Guardian",
                "attachments": [
                    {
                        "color": "danger",
                        "fields": [
                            {
                                "title": "Timestamp",
                                "value": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                                "short": True
                            },
                            {
                                "title": "Hostname",
                                "value": socket.gethostname(),
                                "short": True
                            },
                            {
                                "title": "Mensagem",
                                "value": message,
                                "short": False
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                self.logger.info("Mensagem Slack enviada com sucesso")
                return True
            else:
                self.logger.error(f"Erro ao enviar Slack: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao enviar mensagem Slack: {e}")
            return False
    
    def send_sms(self, message, phone_number=None):
        """Envia SMS (usando serviço Twilio como exemplo)"""
        try:
            # Configurações do Twilio (exemplo)
            account_sid = self.config.get('messaging', {}).get('twilio_account_sid', '')
            auth_token = self.config.get('messaging', {}).get('twilio_auth_token', '')
            from_phone = self.config.get('messaging', {}).get('twilio_from_phone', '')
            to_phone = phone_number or self.config.get('messaging', {}).get('default_phone', '')
            
            if not all([account_sid, auth_token, from_phone, to_phone]):
                self.logger.warning("Configurações do SMS não completas")
                return False
            
            # Formatar mensagem
            sms_message = f"[CyberSec Guardian] {message[:140]}..."  # Limitar a 140 caracteres
            
            # Simular envio de SMS (implementação real dependeria do provedor)
            self.logger.info(f"SMS simulado enviado para {to_phone}: {sms_message}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar SMS: {e}")
            return False
    
    def send_desktop_notification(self, title, message):
        """Envia notificação desktop (Linux/Windows)"""
        try:
            import platform
            
            if platform.system() == "Linux":
                # Usar notify-send no Linux
                os.system(f'notify-send "{title}" "{message}"')
                self.logger.info("Notificação desktop enviada (Linux)")
                return True
                
            elif platform.system() == "Windows":
                # Usar toast notification no Windows
                try:
                    from plyer import notification
                    notification.notify(
                        title=title,
                        message=message,
                        timeout=10
                    )
                    self.logger.info("Notificação desktop enviada (Windows)")
                    return True
                except ImportError:
                    self.logger.warning("Biblioteca plyer não disponível para notificações Windows")
                    return False
                    
            else:
                self.logger.warning(f"Notificações desktop não suportadas para {platform.system()}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao enviar notificação desktop: {e}")
            return False
    
    def broadcast_alert(self, alert_type, message, data=None, attachments=None):
        """Envia alerta para todos os canais configurados"""
        results = {}
        
        # Preparar título baseado no tipo de alerta
        titles = {
            'security': '🔒 Alerta de Segurança',
            'hardware': '🖥️ Alerta de Hardware',
            'network': '🌐 Alerta de Rede',
            'location': '📍 Alerta de Localização',
            'system': '⚙️ Alerta de Sistema',
            'critical': '🚨 ALERTA CRÍTICO'
        }
        
        title = titles.get(alert_type, '⚠️ Alerta do Sistema')
        
        # Email
        try:
            results['email'] = self.send_email(title, message, attachments)
        except Exception as e:
            results['email'] = False
            self.logger.error(f"Erro no envio de email: {e}")
        
        # Telegram
        try:
            results['telegram'] = self.send_telegram_message(message)
        except Exception as e:
            results['telegram'] = False
            self.logger.error(f"Erro no envio de Telegram: {e}")
        
        # Slack
        try:
            results['slack'] = self.send_slack_message(message)
        except Exception as e:
            results['slack'] = False
            self.logger.error(f"Erro no envio de Slack: {e}")
        
        # Notificação Desktop
        try:
            results['desktop'] = self.send_desktop_notification(title, message)
        except Exception as e:
            results['desktop'] = False
            self.logger.error(f"Erro na notificação desktop: {e}")
        
        # Webhook personalizado
        webhook_url = self.config.get('messaging', {}).get('custom_webhook', '')
        if webhook_url:
            try:
                webhook_data = {
                    'alert_type': alert_type,
                    'title': title,
                    'message': message,
                    'data': data
                }
                results['webhook'] = self.send_webhook_notification(webhook_url, webhook_data)
            except Exception as e:
                results['webhook'] = False
                self.logger.error(f"Erro no webhook: {e}")
        
        # Log dos resultados
        successful_channels = [channel for channel, success in results.items() if success]
        failed_channels = [channel for channel, success in results.items() if not success]
        
        if successful_channels:
            self.logger.info(f"Alerta enviado com sucesso via: {', '.join(successful_channels)}")
        
        if failed_channels:
            self.logger.warning(f"Falha no envio via: {', '.join(failed_channels)}")
        
        return results
    
    def add_to_queue(self, alert_type, message, data=None, priority='normal'):
        """Adiciona mensagem à fila de envio"""
        queue_item = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type,
            'message': message,
            'data': data,
            'priority': priority,
            'attempts': 0,
            'max_attempts': 3
        }
        
        # Inserir baseado na prioridade
        if priority == 'critical':
            self.message_queue.insert(0, queue_item)
        else:
            self.message_queue.append(queue_item)
        
        self.logger.info(f"Mensagem adicionada à fila: {alert_type}")
    
    def start_queue_processor(self):
        """Inicia processamento da fila de mensagens"""
        if self.is_running:
            return
        
        self.is_running = True
        self.sending_thread = threading.Thread(target=self._process_queue)
        self.sending_thread.daemon = True
        self.sending_thread.start()
        
        self.logger.info("Processador de fila de mensagens iniciado")
    
    def stop_queue_processor(self):
        """Para o processamento da fila"""
        self.is_running = False
        if self.sending_thread:
            self.sending_thread.join()
        
        self.logger.info("Processador de fila de mensagens parado")
    
    def _process_queue(self):
        """Processa fila de mensagens em background"""
        while self.is_running:
            try:
                if self.message_queue:
                    item = self.message_queue.pop(0)
                    
                    # Tentar enviar
                    results = self.broadcast_alert(
                        item['alert_type'],
                        item['message'],
                        item['data']
                    )
                    
                    # Verificar se pelo menos um canal funcionou
                    if not any(results.values()):
                        item['attempts'] += 1
                        
                        if item['attempts'] < item['max_attempts']:
                            # Recolocar na fila para nova tentativa
                            self.message_queue.append(item)
                            self.logger.warning(f"Recolocando mensagem na fila (tentativa {item['attempts']})")
                        else:
                            self.logger.error("Mensagem descartada após múltiplas tentativas")
                
                time.sleep(5)  # Aguardar 5 segundos entre processamentos
                
            except Exception as e:
                self.logger.error(f"Erro no processamento da fila: {e}")
                time.sleep(10)
    
    def send_test_messages(self):
        """Envia mensagens de teste para todos os canais"""
        test_message = "Este é um teste do sistema de mensagens CyberSec Guardian"
        
        self.logger.info("Enviando mensagens de teste...")
        
        results = self.broadcast_alert('system', test_message, {'test': True})
        
        return results
    
    def get_queue_status(self):
        """Retorna status da fila de mensagens"""
        return {
            'queue_size': len(self.message_queue),
            'is_running': self.is_running,
            'pending_messages': [
                {
                    'timestamp': item['timestamp'],
                    'alert_type': item['alert_type'],
                    'priority': item['priority'],
                    'attempts': item['attempts']
                }
                for item in self.message_queue
            ]
        }

# Exemplo de uso
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Configuração de exemplo
    config = {
        'messaging': {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'email_from': 'security@company.com',
            'email_to': 'admin@company.com',
            'email_password': 'your_password_here',
            'telegram_bot_token': 'your_bot_token_here',
            'telegram_chat_id': 'your_chat_id_here'
        }
    }
    
    sender = MessageSender(config)
    
    # Teste de envio
    print("=== TESTE DE ENVIO DE MENSAGENS ===")
    results = sender.send_test_messages()
    print(json.dumps(results, indent=2))