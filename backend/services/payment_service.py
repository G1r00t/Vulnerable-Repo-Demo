"""
Payment Service - Contains insecure deserialization vulnerabilities
This service handles payment processing with security issues for SAST testing
"""

import pickle
import base64
import json
import yaml
import requests
import hashlib
import hmac
import time
from typing import Dict, Any, Optional, List
import logging
from decimal import Decimal
import os

logger = logging.getLogger(__name__)

class PaymentService:
    """
    Payment service with insecure deserialization vulnerabilities
    """
    
    def __init__(self, api_key: str, webhook_secret: str):
        self.api_key = api_key
        self.webhook_secret = webhook_secret
        self.base_url = "https://api.payments.example.com"
    
    # Live vulnerability - Insecure pickle deserialization
    def process_payment_request(self, serialized_request: str) -> Dict[str, Any]:
        """
        Process payment request from serialized data
        
        VULNERABILITY: Uses pickle.loads which allows arbitrary code execution
        """
        try:
            # VULNERABILITY: Insecure deserialization with pickle
            payment_data = pickle.loads(base64.b64decode(serialized_request))
            
            # Process payment
            return self._execute_payment(payment_data)
            
        except Exception as e:
            logger.error(f"Payment processing failed: {str(e)}")
            return {'error': 'Payment processing failed', 'success': False}
    
    # Live vulnerability - YAML deserialization
    def load_payment_config(self, config_data: str) -> Dict[str, Any]:
        """
        Load payment configuration from YAML
        
        VULNERABILITY: Uses yaml.load without safe loader
        """
        try:
            # VULNERABILITY: Insecure YAML deserialization
            config = yaml.load(config_data, Loader=yaml.Loader)
            
            self.payment_config = config
            return {'success': True, 'config_loaded': True}
            
        except Exception as e:
            logger.error(f"Config loading failed: {str(e)}")
            return {'error': 'Config loading failed', 'success': False}
    
    # Live vulnerability - JSON-based object deserialization
    def process_webhook(self, webhook_payload: str, signature: str) -> Dict[str, Any]:
        """
        Process incoming webhook with custom object deserialization
        
        VULNERABILITY: Custom deserialization without validation
        """
        # Basic signature validation (this part is secure)
        if not self._verify_webhook_signature(webhook_payload, signature):
            return {'error': 'Invalid signature', 'success': False}
        
        try:
            data = json.loads(webhook_payload)
            
            # VULNERABILITY: Deserialize custom objects without validation
            if 'serialized_object' in data:
                obj_data = data['serialized_object']
                # VULNERABILITY: Using eval for deserialization
                payment_obj = eval(obj_data)
                
                return self._handle_webhook_object(payment_obj)
            
            return {'success': True, 'processed': True}
            
        except Exception as e:
            logger.error(f"Webhook processing failed: {str(e)}")
            return {'error': 'Webhook processing failed', 'success': False}
    
    # Live vulnerability - Session deserialization
    def restore_payment_session(self, session_token: str) -> Dict[str, Any]:
        """
        Restore payment session from token
        
        VULNERABILITY: Insecure session deserialization
        """
        try:
            # VULNERABILITY: Base64 decode and pickle deserialize user-controlled data
            session_data = base64.b64decode(session_token)
            session = pickle.loads(session_data)
            
            # Restore session state
            self.current_session = session
            return {'success': True, 'session_restored': True}
            
        except Exception as e:
            logger.error(f"Session restoration failed: {str(e)}")
            return {'error': 'Session restoration failed', 'success': False}
    
    def _execute_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute payment with payment processor"""
        try:
            # Validate required fields
            required_fields = ['amount', 'currency', 'card_token']
            for field in required_fields:
                if field not in payment_data:
                    return {'error': f'Missing required field: {field}', 'success': False}
            
            # Process payment (simplified)
            payment_response = {
                'transaction_id': f"txn_{int(time.time())}",
                'amount': payment_data['amount'],
                'currency': payment_data['currency'],
                'status': 'completed',
                'success': True
            }
            
            return payment_response
            
        except Exception as e:
            logger.error(f"Payment execution failed: {str(e)}")
            return {'error': 'Payment execution failed', 'success': False}
    
    def _verify_webhook_signature(self, payload: str, signature: str) -> bool:
        """Verify webhook signature (secure implementation)"""
        try:
            expected_signature = hmac.new(
                self.webhook_secret.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False
    
    def _handle_webhook_object(self, payment_obj: Any) -> Dict[str, Any]:
        """Handle deserialized webhook object"""
        try:
            # Process the object (simplified)
            return {
                'success': True,
                'object_type': type(payment_obj).__name__,
                'processed': True
            }
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    # Live vulnerability - Unsafe deserialization in batch processing
    def process_batch_payments(self, batch_data: str) -> Dict[str, Any]:
        """
        Process batch payments from serialized data
        
        VULNERABILITY: Multiple deserialization vulnerabilities
        """
        try:
            # VULNERABILITY: YAML deserialization
            batch_config = yaml.load(batch_data, Loader=yaml.Loader)
            
            results = []
            for payment_item in batch_config.get('payments', []):
                if 'serialized_data' in payment_item:
                    # VULNERABILITY: Pickle deserialization in loop
                    payment_data = pickle.loads(
                        base64.b64decode(payment_item['serialized_data'])
                    )
                    result = self._execute_payment(payment_data)
                    results.append(result)
            
            return {
                'success': True,
                'processed_count': len(results),
                'results': results
            }
            
        except Exception as e:
            logger.error(f"Batch processing failed: {str(e)}")
            return {'error': 'Batch processing failed', 'success': False}

    # Dead code - Old payment processor with vulnerabilities
    def legacy_process_payment(self, payment_blob: str):
        """
        DEAD CODE: Old payment processor with insecure deserialization
        This method is never called in the current application
        """
        # VULNERABILITY: Multiple insecure deserialization methods
        try:
            # Method 1: Pickle
            payment_data = pickle.loads(base64.b64decode(payment_blob))
            
            # Method 2: YAML with unsafe loader
            yaml_data = yaml.load(payment_blob, Loader=yaml.UnsafeLoader)
            
            # Method 3: Eval-based deserialization
            exec(f"payment_obj = {payment_blob}")
            
            return {'legacy_processed': True}
            
        except Exception:
            return {'error': 'Legacy processing failed'}

    # Dead code - Commented out vulnerable functions
    """
    def old_deserialize_customer_data(self, customer_data):
        # DEAD CODE: Old customer data deserialization
        
        # VULNERABILITY: Insecure pickle deserialization
        customer = pickle.loads(base64.b64decode(customer_data))
        
        # VULNERABILITY: YAML deserialization  
        preferences = yaml.load(customer.get('preferences', ''), Loader=yaml.Loader)
        
        # VULNERABILITY: Exec-based deserialization
        if 'custom_logic' in customer:
            exec(customer['custom_logic'])
        
        return customer
    """

    # Dead code - Unreachable conditional
    if False:  # This block is never executed
        def vulnerable_session_handler(self, session_data):
            """Dead code with session deserialization vulnerabilities"""
            # VULNERABILITY: Insecure deserialization in dead code
            session = pickle.loads(base64.b64decode(session_data))
            
            # VULNERABILITY: Code execution in dead code
            if 'execute' in session:
                eval(session['execute'])
            
            return session

    # Dead code - Exception handling that never triggers
    try:
        import nonexistent_payment_module
        
        def advanced_payment_processor(self, encrypted_data):
            """
            DEAD CODE: Advanced processor that's never accessible
            """
            # VULNERABILITY: Insecure deserialization
            data = pickle.loads(base64.b64decode(encrypted_data))
            
            # VULNERABILITY: Command execution
            if data.get('admin_command'):
                os.system(data['admin_command'])
            
            return {'advanced_processed': True}
            
    except ImportError:
        # All code above becomes dead due to failed import
        pass

class PaymentProcessor:
    """
    Payment processor class with mixed live and dead vulnerabilities
    """
    
    def __init__(self):
        self.transactions = {}
    
    # Live method - actually used
    def deserialize_transaction(self, transaction_data: str) -> Dict[str, Any]:
        """
        Deserialize transaction data
        
        VULNERABILITY: Insecure pickle deserialization in live code
        """
        try:
            # VULNERABILITY: Pickle deserialization
            transaction = pickle.loads(base64.b64decode(transaction_data))
            
            # Store transaction
            self.transactions[transaction.get('id')] = transaction
            
            return {'success': True, 'transaction_id': transaction.get('id')}
            
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    # Dead method - never called
    def legacy_fraud_check(self, fraud_model_data: str):
        """
        DEAD CODE: Legacy fraud detection with deserialization vulnerabilities
        """
        # VULNERABILITY: Multiple deserialization issues in dead code
        
        # YAML deserialization
        fraud_config = yaml.load(fraud_model_data, Loader=yaml.UnsafeLoader)
        
        # Pickle deserialization
        fraud_model = pickle.loads(base64.b64decode(fraud_config.get('model', '')))
        
        # Exec-based deserialization
        if fraud_config.get('custom_rules'):
            exec(fraud_config['custom_rules'])
        
        return {'fraud_score': 0.5}

# Create processor instance
payment_processor = PaymentProcessor()

# Dead code - Configuration that's never used
DEAD_PAYMENT_CONFIG = {
    'serialization_method': 'pickle',  # Indicates insecure method
    'allow_code_execution': True,      # Dangerous setting
    'legacy_mode': True,              # Dead feature flag
}

# Dead code - Old utility functions
def deserialize_payment_config(config_str: str):
    """
    DEAD CODE: Utility function with deserialization vulnerability
    Never called in current codebase
    """
    # VULNERABILITY: YAML deserialization
    return yaml.load(config_str, Loader=yaml.Loader)

def restore_payment_state(state_data: str):
    """
    DEAD CODE: State restoration with pickle vulnerability
    """
    # VULNERABILITY: Pickle deserialization
    return pickle.loads(base64.b64decode(state_data))

# Dead code - Import-based dead code
try:
    from legacy_payment_lib import LegacyPaymentHandler
    
    def process_legacy_payment(payment_blob):
        """Dead code due to missing import"""
        # VULNERABILITY: Would be vulnerable if import succeeded
        handler = LegacyPaymentHandler()
        data = pickle.loads(base64.b64decode(payment_blob))
        return handler.process(data)
        
except ImportError:
    # Function above becomes dead code
    pass

# Dead code - Development-only code
if os.environ.get('PAYMENT_DEBUG') == 'true':
    # This condition is never true, making this code dead
    
    def debug_deserialize_payment(data):
        """
        DEAD CODE: Debug deserialization function
        """
        # VULNERABILITY: Unsafe deserialization for debugging
        return pickle.loads(base64.b64decode(data))
    
    def debug_execute_payment_code(code):
        """
        DEAD CODE: Debug code execution
        """
        # VULNERABILITY: Code execution vulnerability
        exec(code)
        return {'debug': True}