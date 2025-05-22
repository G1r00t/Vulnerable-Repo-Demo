"""
Email Service - Clean implementation with proper security practices
This service demonstrates secure coding practices and should have zero vulnerabilities
"""

import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional, Dict, Any
import re
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class EmailService:
    """
    Clean email service implementation with proper security practices
    """
    
    def __init__(self, smtp_host: str, smtp_port: int, username: str, password: str):
        """
        Initialize email service with secure configuration
        
        Args:
            smtp_host: SMTP server hostname 
            smtp_port: SMTP server port
            username: SMTP username
            password: SMTP password
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        
        # Validate email configuration
        self._validate_config()
        
        # Create secure SSL context
        self.ssl_context = ssl.create_default_context()
        
    def _validate_config(self) -> None:
        """Validate email configuration parameters"""
        if not self.smtp_host or not isinstance(self.smtp_host, str):
            raise ValueError("SMTP host must be a non-empty string")
        
        if not isinstance(self.smtp_port, int) or self.smtp_port <= 0:
            raise ValueError("SMTP port must be a positive integer")
            
        if not self.username or not isinstance(self.username, str):
            raise ValueError("Username must be a non-empty string")
            
        if not self.password or not isinstance(self.password, str):
            raise ValueError("Password must be a non-empty string")
    
    def _validate_email(self, email: str) -> bool:
        """
        Validate email address format
        
        Args:
            email: Email address to validate
            
        Returns:
            bool: True if email is valid, False otherwise
        """
        if not email or not isinstance(email, str):
            return False
            
        # RFC 5322 compliant email regex pattern
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _sanitize_content(self, content: str) -> str:
        """
        Sanitize email content to prevent injection attacks
        
        Args:
            content: Raw email content
            
        Returns:
            str: Sanitized content
        """
        if not isinstance(content, str):
            content = str(content)
            
        # Remove potentially dangerous characters
        dangerous_chars = ['\r\n', '\n\r', '\r', '\n']
        for char in dangerous_chars:
            content = content.replace(char, ' ')
            
        return content.strip()
    
    def send_email(self, 
                   to_addresses: List[str], 
                   subject: str, 
                   body: str, 
                   from_address: Optional[str] = None,
                   cc_addresses: Optional[List[str]] = None,
                   bcc_addresses: Optional[List[str]] = None,
                   attachments: Optional[List[Dict[str, Any]]] = None) -> bool:
        """
        Send email with proper validation and security measures
        
        Args:
            to_addresses: List of recipient email addresses
            subject: Email subject line
            body: Email body content
            from_address: Sender email address (optional)
            cc_addresses: List of CC recipients (optional)
            bcc_addresses: List of BCC recipients (optional)
            attachments: List of file attachments (optional)
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            # Validate input parameters
            if not to_addresses or not isinstance(to_addresses, list):
                logger.error("Invalid to_addresses parameter")
                return False
                
            # Validate all email addresses
            all_addresses = to_addresses.copy()
            if cc_addresses:
                all_addresses.extend(cc_addresses)
            if bcc_addresses:
                all_addresses.extend(bcc_addresses)
                
            for email in all_addresses:
                if not self._validate_email(email):
                    logger.error(f"Invalid email address: {email}")
                    return False
            
            # Sanitize content
            subject = self._sanitize_content(subject)
            body = self._sanitize_content(body)
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_address or self.username
            msg['To'] = ', '.join(to_addresses)
            msg['Subject'] = subject
            
            if cc_addresses:
                msg['Cc'] = ', '.join(cc_addresses)
            
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            # Add attachments if provided
            if attachments:
                for attachment in attachments:
                    if not self._add_attachment(msg, attachment):
                        logger.warning(f"Failed to add attachment: {attachment}")
            
            # Send email using secure connection
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls(context=self.ssl_context)
                server.login(self.username, self.password)
                
                # Send to all recipients
                all_recipients = to_addresses.copy()
                if cc_addresses:
                    all_recipients.extend(cc_addresses)
                if bcc_addresses:
                    all_recipients.extend(bcc_addresses)
                
                server.send_message(msg, to_addrs=all_recipients)
                
            logger.info(f"Email sent successfully to {len(all_recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False
    
    def _add_attachment(self, msg: MIMEMultipart, attachment: Dict[str, Any]) -> bool:
        """
        Safely add attachment to email message
        
        Args:
            msg: Email message object
            attachment: Attachment dictionary with 'filename' and 'content' keys
            
        Returns:
            bool: True if attachment added successfully, False otherwise
        """
        try:
            filename = attachment.get('filename')
            content = attachment.get('content')
            
            if not filename or not content:
                return False
                
            # Validate filename (no path traversal)
            filename = os.path.basename(filename)
            if not filename or filename.startswith('.'):
                return False
                
            # Create attachment
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(content)
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {filename}'
            )
            
            msg.attach(part)
            return True
            
        except Exception as e:
            logger.error(f"Failed to add attachment: {str(e)}")
            return False
    
    def send_template_email(self, 
                          template_name: str, 
                          to_addresses: List[str],
                          template_data: Dict[str, Any]) -> bool:
        """
        Send email using predefined template
        
        Args:
            template_name: Name of email template
            to_addresses: List of recipient email addresses
            template_data: Data to populate template variables
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            # Load and validate template
            template_path = self._get_template_path(template_name)
            if not template_path or not template_path.exists():
                logger.error(f"Template not found: {template_name}")
                return False
                
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            # Safely substitute template variables
            subject, body = self._process_template(template_content, template_data)
            
            return self.send_email(to_addresses, subject, body)
            
        except Exception as e:
            logger.error(f"Failed to send template email: {str(e)}")
            return False
    
    def _get_template_path(self, template_name: str) -> Optional[Path]:
        """
        Get secure path to email template
        
        Args:
            template_name: Name of template file
            
        Returns:
            Path: Path to template file or None if invalid
        """
        # Validate template name (no path traversal)
        if not template_name or not isinstance(template_name, str):
            return None
            
        # Remove any path separators
        template_name = os.path.basename(template_name)
        
        # Only allow alphanumeric characters and underscores
        if not re.match(r'^[a-zA-Z0-9_]+\.html$', template_name):
            return None
            
        # Construct safe path
        templates_dir = Path(__file__).parent.parent / 'templates' / 'email'
        template_path = templates_dir / template_name
        
        # Ensure path is within templates directory
        try:
            template_path.resolve().relative_to(templates_dir.resolve())
            return template_path
        except ValueError:
            return None
    
    def _process_template(self, template_content: str, template_data: Dict[str, Any]) -> tuple:
        """
        Safely process email template
        
        Args:
            template_content: Raw template content
            template_data: Data for template variables
            
        Returns:
            tuple: (subject, body) processed from template
        """
        # Simple and safe template processing
        lines = template_content.split('\n')
        subject = ""
        body_lines = []
        
        in_body = False
        for line in lines:
            if line.startswith('Subject:'):
                subject = line.replace('Subject:', '').strip()
            elif line.strip() == '---':
                in_body = True
            elif in_body:
                body_lines.append(line)
        
        body = '\n'.join(body_lines)
        
        # Safe variable substitution (only simple string replacement)
        for key, value in template_data.items():
            if isinstance(key, str) and isinstance(value, str):
                # Sanitize key and value
                key = re.sub(r'[^a-zA-Z0-9_]', '', key)
                value = self._sanitize_content(str(value))
                
                subject = subject.replace(f'{{{key}}}', value)
                body = body.replace(f'{{{key}}}', value)
        
        return subject, body
    
    def validate_email_list(self, email_list: List[str]) -> List[str]:
        """
        Validate and filter email list
        
        Args:
            email_list: List of email addresses to validate
            
        Returns:
            List[str]: List of valid email addresses
        """
        valid_emails = []
        
        if not isinstance(email_list, list):
            return valid_emails
            
        for email in email_list:
            if self._validate_email(email):
                valid_emails.append(email)
            else:
                logger.warning(f"Invalid email address filtered: {email}")
        
        return valid_emails
    
    def get_delivery_status(self, message_id: str) -> Dict[str, Any]:
        """
        Get email delivery status (placeholder for future implementation)
        
        Args:
            message_id: Message ID to check status for
            
        Returns:
            Dict: Delivery status information
        """
        # This is a placeholder - actual implementation would integrate
        # with email service provider APIs
        return {
            'message_id': message_id,
            'status': 'unknown',
            'timestamp': None,
            'error': 'Status checking not implemented'
        }