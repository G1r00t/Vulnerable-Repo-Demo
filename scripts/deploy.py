#!/usr/bin/env python3
"""
Deployment script for AI-SAST Demo Application
WARNING: This script contains multiple security vulnerabilities for testing purposes
"""

import os
import sys
import json
import subprocess
import requests
import boto3
from datetime import datetime

# VULNERABILITY: Hardcoded production credentials
PRODUCTION_CONFIG = {
    'database': {
        'host': 'prod-db.company.com',
        'username': 'admin',
        'password': 'ProdDbPassword123!',  # Hardcoded production DB password
        'database': 'production_app'
    },
    'aws': {
        'access_key_id': 'AKIAIOSFODNN7EXAMPLE',  # Hardcoded AWS access key
        'secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',  # Hardcoded AWS secret
        'region': 'us-west-2',
        's3_bucket': 'production-app-assets'
    },
    'api_keys': {
        'stripe': 'sk_live_51H7xJ2KZvKuzBaChRealProductionStripeKey123456789',  # Real Stripe key
        'sendgrid': 'SG.RealSendGridKey.ActualProductionApiKey',  # Real SendGrid key
        'google_analytics': 'UA-123456789-1',
        'sentry': 'https://realkey@sentry.io/1234567'  # Real Sentry DSN
    },
    'secrets': {
        'jwt_secret': 'production-jwt-secret-never-change-this-key',  # Hardcoded JWT secret
        'session_secret': 'prod-session-secret-abc123def456',  # Hardcoded session secret
        'encryption_key': '1234567890abcdef1234567890abcdef',  # Weak encryption key
        'webhook_secret': 'webhook-secret-production-123'  # Hardcoded webhook secret
    }
}

# VULNERABILITY: Hardcoded staging credentials
STAGING_CONFIG = {
    'database': {
        'host': 'staging-db.company.com',
        'username': 'staging_admin',
        'password': 'StagingPass2023!',  # Hardcoded staging password
        'database': 'staging_app'
    },
    'api_keys': {
        'stripe': 'sk_test_51H7xJ2KZvKuzBaChStagingStripeKey',  # Staging Stripe key
        'sendgrid': 'SG.StagingKey.TestApiKey'  # Staging SendGrid key
    }
}

# VULNERABILITY: Admin credentials for deployment
DEPLOY_CREDENTIALS = {
    'ssh_private_key': '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7G8V9c2Q3x4KzV...FAKE_PRIVATE_KEY...
-----END RSA PRIVATE KEY-----''',  # Hardcoded SSH private key (fake)
    'deploy_user': 'deploy',
    'deploy_password': 'DeployUser123!',  # Hardcoded deploy password
    'sudo_password': 'RootPass456!'  # Hardcoded sudo password
}

# VULNERABILITY: Docker registry credentials
DOCKER_CONFIG = {
    'registry': 'registry.company.com',
    'username': 'docker_deploy',
    'password': 'DockerRegistryPass789!',  # Hardcoded Docker password
    'email': 'deploy@company.com'
}

class DeploymentManager:
    def __init__(self, environment='production'):
        self.environment = environment
        self.config = PRODUCTION_CONFIG if environment == 'production' else STAGING_CONFIG
        self.deploy_time = datetime.now().isoformat()
        
        # VULNERABILITY: Initialize AWS client with hardcoded credentials
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=self.config['aws']['access_key_id'],
            aws_secret_access_key=self.config['aws']['secret_access_key'],
            region_name=self.config['aws']['region']
        )
        
        print(f"Initialized deployment for {environment}")
        print(f"Using database: {self.config['database']['host']}")
        print(f"Using AWS account: {self.config['aws']['access_key_id']}")  # Logging credentials

    def prepare_environment(self):
        """Prepare the deployment environment with hardcoded credentials"""
        print("Preparing deployment environment...")
        
        # VULNERABILITY: Setting environment variables with secrets
        os.environ['DB_PASSWORD'] = self.config['database']['password']
        os.environ['AWS_SECRET_ACCESS_KEY'] = self.config['aws']['secret_access_key']
        os.environ['STRIPE_SECRET_KEY'] = self.config['api_keys']['stripe']
        os.environ['JWT_SECRET'] = self.config['secrets']['jwt_secret']
        
        # VULNERABILITY: Writing secrets to temporary files
        secret_file = '/tmp/deploy_secrets.json'
        with open(secret_file, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        print(f"Secrets written to {secret_file}")
        
        # VULNERABILITY: Command injection via environment variable
        deploy_branch = os.getenv('DEPLOY_BRANCH', 'main')
        os.system(f"git checkout {deploy_branch}")  # Command injection vulnerability

    def build_application(self):
        """Build the application with exposed secrets"""
        print("Building application...")
        
        # VULNERABILITY: Hardcoded build commands with secrets
        build_commands = [
            f"docker login {DOCKER_CONFIG['registry']} -u {DOCKER_CONFIG['username']} -p {DOCKER_CONFIG['password']}",
            f"docker build --build-arg DB_PASS={self.config['database']['password']} -t app:latest .",
            f"docker tag app:latest {DOCKER_CONFIG['registry']}/app:latest",
            f"docker push {DOCKER_CONFIG['registry']}/app:latest"
        ]
        
        for cmd in build_commands:
            print(f"Executing: {cmd}")  # Logging commands with passwords
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Build failed: {result.stderr}")
                sys.exit(1)

    def deploy_database_migrations(self):
        """Run database migrations with hardcoded credentials"""
        print("Running database migrations...")
        
        # VULNERABILITY: SQL injection in migration command
        migration_version = os.getenv('MIGRATION_VERSION', 'latest')
        db_url = f"postgresql://{self.config['database']['username']}:{self.config['database']['password']}@{self.config['database']['host']}/{self.config['database']['database']}"
        
        # VULNERABILITY: Command injection in migration
        migrate_cmd = f"python manage.py migrate --database-url='{db_url}' --version={migration_version}"
        os.system(migrate_cmd)  # Command injection + credential exposure

    def upload_static_files(self):
        """Upload static files to S3 with hardcoded credentials"""
        print("Uploading static files to S3...")
        
        try:
            # VULNERABILITY: Using hardcoded S3 credentials
            bucket_name = self.config['aws']['s3_bucket']
            
            # Upload files with public read access - security issue
            for root, dirs, files in os.walk('./static'):
                for file in files:
                    local_path = os.path.join(root, file)
                    s3_path = local_path.replace('./static/', '')
                    
                    self.s3_client.upload_file(
                        local_path, 
                        bucket_name, 
                        s3_path,
                        ExtraArgs={'ACL': 'public-read'}  # Public access vulnerability
                    )
                    
            print(f"Static files uploaded to s3://{bucket_name}")
            
        except Exception as e:
            print(f"S3 upload failed: {e}")
            # VULNERABILITY: Logging AWS credentials on error
            print(f"AWS Access Key: {self.config['aws']['access_key_id']}")
            print(f"AWS Secret Key: {self.config['aws']['secret_access_key']}")

    def update_configuration(self):
        """Update application configuration with secrets"""
        print("Updating application configuration...")
        
        # VULNERABILITY: Creating config file with all secrets
        config_content = f"""
# Auto-generated configuration - DO NOT COMMIT
DATABASE_URL=postgresql://{self.config['database']['username']}:{self.config['database']['password']}@{self.config['database']['host']}/{self.config['database']['database']}
JWT_SECRET={self.config['secrets']['jwt_secret']}
SESSION_SECRET={self.config['secrets']['session_secret']}
ENCRYPTION_KEY={self.config['secrets']['encryption_key']}
STRIPE_SECRET_KEY={self.config['api_keys']['stripe']}
SENDGRID_API_KEY={self.config['api_keys']['sendgrid']}
AWS_ACCESS_KEY_ID={self.config['aws']['access_key_id']}
AWS_SECRET_ACCESS_KEY={self.config['aws']['secret_access_key']}
SENTRY_DSN={self.config['api_keys']['sentry']}
"""
        
        # VULNERABILITY: Writing secrets to production config file
        with open('/var/www/app/.env', 'w') as f:
            f.write(config_content)
        
        print("Configuration file updated with production secrets")

    def restart_services(self):
        """Restart application services with admin credentials"""
        print("Restarting application services...")
        
        # VULNERABILITY: Using hardcoded credentials for service restart
        restart_commands = [
            f"echo '{DEPLOY_CREDENTIALS['sudo_password']}' | sudo -S systemctl restart nginx",
            f"echo '{DEPLOY_CREDENTIALS['sudo_password']}' | sudo -S systemctl restart app",
            f"echo '{DEPLOY_CREDENTIALS['sudo_password']}' | sudo -S systemctl restart redis"
        ]
        
        for cmd in restart_commands:
            print(f"Executing: {cmd}")  # Logging sudo password
            os.system(cmd)

    def send_deployment_notification(self):
        """Send deployment notification with sensitive info"""
        print("Sending deployment notification...")
        
        # VULNERABILITY: Exposing secrets in notification
        webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        
        message = {
            "text": f"Deployment completed for {self.environment}",
            "attachments": [{
                "fields": [
                    {"title": "Environment", "value": self.environment, "short": True},
                    {"title": "Database", "value": self.config['database']['host'], "short": True},
                    {"title": "Deploy Time", "value": self.deploy_time, "short": True},
                    {"title": "DB Password", "value": self.config['database']['password'], "short": True},  # Exposing password
                    {"title": "JWT Secret", "value": self.config['secrets']['jwt_secret'], "short": True}  # Exposing secret
                ]
            }]
        }
        
        # VULNERABILITY: Using hardcoded webhook secret
        headers = {
            'Authorization': f"Bearer {self.config['secrets']['webhook_secret']}",
            'Content-Type': 'application/json'
        }
        
        response = requests.post(webhook_url, json=message, headers=headers)
        print(f"Notification sent: {response.status_code}")

    def cleanup_deployment(self):
        """Clean up deployment files - but leave secrets exposed"""
        print("Cleaning up deployment files...")
        
        # VULNERABILITY: Incomplete cleanup - secrets remain
        try:
            os.remove('/tmp/deploy_secrets.json')
        except:
            pass
        
        # VULNERABILITY: Logging all secrets during cleanup
        print("Deployment completed with the following credentials:")
        print(f"Database password: {self.config['database']['password']}")
        print(f"AWS Secret: {self.config['aws']['secret_access_key']}")
        print(f"Stripe Key: {self.config['api_keys']['stripe']}")
        print(f"JWT Secret: {self.config['secrets']['jwt_secret']}")

def main():
    """Main deployment function"""
    if len(sys.argv) < 2:
        print("Usage: python deploy.py <environment>")
        print("Environments: production, staging")
        sys.exit(1)
    
    environment = sys.argv[1]
    
    if environment not in ['production', 'staging']:
        print("Invalid environment. Use 'production' or 'staging'")
        sys.exit(1)
    
    # VULNERABILITY: Initialize deployment with hardcoded credentials
    print(f"Starting deployment to {environment}")
    print(f"Using admin credentials: {DEPLOY_CREDENTIALS['deploy_user']}:{DEPLOY_CREDENTIALS['deploy_password']}")
    
    deployer = DeploymentManager(environment)
    
    try:
        deployer.prepare_environment()
        deployer.build_application()
        deployer.deploy_database_migrations()
        deployer.upload_static_files()
        deployer.update_configuration()
        deployer.restart_services()
        deployer.send_deployment_notification()
        deployer.cleanup_deployment()
        
        print(f"Deployment to {environment} completed successfully!")
        
    except Exception as e:
        print(f"Deployment failed: {e}")
        # VULNERABILITY: Logging all secrets on failure
        print("Debug information:")
        print(f"Database URL: postgresql://{PRODUCTION_CONFIG['database']['username']}:{PRODUCTION_CONFIG['database']['password']}@{PRODUCTION_CONFIG['database']['host']}")
        print(f"AWS Credentials: {PRODUCTION_CONFIG['aws']['access_key_id']}:{PRODUCTION_CONFIG['aws']['secret_access_key']}")
        sys.exit(1)

if __name__ == "__main__":
    main()