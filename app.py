from flask import Flask, render_template, request, jsonify, session
import hashlib
import secrets
import json
import math
import random
from typing import Dict, List, Tuple, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from collections import defaultdict
import bisect

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

class DistributionTransformingEncoder:
    """
    Base class for Distribution-Transforming Encoders (DTEs)
    Maps messages to uniform seed space according to message probability distribution
    """
    
    def __init__(self, message_space: List[Any], probabilities: List[float]):
        self.message_space = message_space
        self.probabilities = probabilities
        self.seed_bits = 32  # Use 32-bit seed space
        self.seed_max = 2**self.seed_bits - 1
        
        # Build cumulative distribution and interval mapping
        self._build_intervals()
    
    def _build_intervals(self):
        """Build interval mapping for messages based on probability distribution"""
        # Normalize probabilities
        total_prob = sum(self.probabilities)
        self.normalized_probs = [p / total_prob for p in self.probabilities]
        
        # Build cumulative distribution
        self.cumulative_probs = []
        cum_sum = 0.0
        for prob in self.normalized_probs:
            cum_sum += prob
            self.cumulative_probs.append(cum_sum)
        
        # Map messages to seed intervals
        self.message_intervals = {}
        self.interval_to_message = {}
        
        for i, message in enumerate(self.message_space):
            # Calculate interval bounds
            start_prob = self.cumulative_probs[i-1] if i > 0 else 0.0
            end_prob = self.cumulative_probs[i]
            
            # Map to seed space
            start_seed = int(start_prob * (self.seed_max + 1))
            end_seed = int(end_prob * (self.seed_max + 1)) - 1
            
            if end_seed < start_seed:
                end_seed = start_seed
                
            self.message_intervals[message] = (start_seed, end_seed)
            
            # Store reverse mapping for all seeds in this interval
            for seed in range(start_seed, end_seed + 1):
                self.interval_to_message[seed] = message
    
    def encode(self, message: Any) -> int:
        """Encode a message to a random seed in its assigned interval"""
        if message not in self.message_intervals:
            raise ValueError(f"Message {message} not in message space")
        
        start_seed, end_seed = self.message_intervals[message]
        return secrets.randbelow(end_seed - start_seed + 1) + start_seed
    
    def decode(self, seed: int) -> Any:
        """Decode a seed back to its corresponding message"""
        seed = seed % (self.seed_max + 1)  # Ensure seed is in valid range
        
        if seed in self.interval_to_message:
            return self.interval_to_message[seed]
        
        # If seed not found, find closest interval
        closest_seed = min(self.interval_to_message.keys(), 
                          key=lambda x: abs(x - seed))
        return self.interval_to_message[closest_seed]

class CreditCardDTE(DistributionTransformingEncoder):
    """DTE for credit card numbers with realistic distribution"""
    
    def __init__(self):
        # Generate realistic credit card message space
        credit_cards = self._generate_credit_card_space()
        
        # Realistic probability distribution (Visa most common, then Mastercard, etc.)
        probabilities = []
        for card in credit_cards:
            if card.startswith('4'):  # Visa
                probabilities.append(0.45)
            elif card.startswith('5'):  # Mastercard
                probabilities.append(0.35)
            elif card.startswith('3'):  # Amex
                probabilities.append(0.15)
            else:  # Others
                probabilities.append(0.05)
        
        super().__init__(credit_cards, probabilities)
    
    def _generate_credit_card_space(self) -> List[str]:
        """Generate a sample space of valid credit card numbers"""
        cards = []
        
        # Generate Visa cards (start with 4)
        for i in range(50):
            card = self._generate_valid_card('4')
            if card:
                cards.append(card)
        
        # Generate Mastercard (start with 5)
        for i in range(40):
            card = self._generate_valid_card('5')
            if card:
                cards.append(card)
        
        # Generate Amex (start with 3)
        for i in range(20):
            card = self._generate_valid_card('3')
            if card:
                cards.append(card)
        
        # Generate others
        for i in range(10):
            card = self._generate_valid_card('6')
            if card:
                cards.append(card)
        
        return list(set(cards))  # Remove duplicates
    
    def _generate_valid_card(self, prefix: str) -> str:
        """Generate a valid credit card number with Luhn checksum"""
        # Generate 15 random digits after prefix
        digits = [int(prefix)]
        for _ in range(14):
            digits.append(secrets.randbelow(10))
        
        # Calculate Luhn checksum
        checksum = self._calculate_luhn_checksum(digits)
        digits.append(checksum)
        
        return ''.join(map(str, digits))
    
    def _calculate_luhn_checksum(self, digits: List[int]) -> int:
        """Calculate Luhn algorithm checksum"""
        total = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 0:  # Every second digit from right
                doubled = digit * 2
                total += doubled if doubled < 10 else doubled - 9
            else:
                total += digit
        
        return (10 - (total % 10)) % 10

class PasswordDTE(DistributionTransformingEncoder):
    """DTE for common passwords with realistic frequency distribution"""
    
    def __init__(self):
        # Common passwords with frequency estimates
        passwords_freq = [
            ("password", 0.15),
            ("123456", 0.12),
            ("password123", 0.08),
            ("admin", 0.06),
            ("qwerty", 0.05),
            ("letmein", 0.04),
            ("welcome", 0.04),
            ("monkey", 0.03),
            ("dragon", 0.03),
            ("secret", 0.03),
            ("password1", 0.03),
            ("123456789", 0.03),
            ("football", 0.02),
            ("princess", 0.02),
            ("charlie", 0.02),
            ("login", 0.02),
            ("master", 0.02),
            ("sunshine", 0.02),
            ("shadow", 0.02),
            ("trustno1", 0.02),
            ("iloveyou", 0.02),
            ("superman", 0.01),
            ("batman", 0.01),
            ("spider", 0.01),
            ("computer", 0.01),
            ("internet", 0.01),
            ("default", 0.01),
            ("guest", 0.01),
            ("user", 0.01),
            ("test", 0.01),
            ("demo", 0.01),
            ("sample", 0.01),
            ("temp", 0.01),
            ("abc123", 0.01),
            ("pass", 0.01)
        ]
        
        passwords = [p[0] for p in passwords_freq]
        probabilities = [p[1] for p in passwords_freq]
        
        super().__init__(passwords, probabilities)

class BiometricDTE(DistributionTransformingEncoder):
    """DTE for simplified biometric templates (simulated as binary strings)"""
    
    def __init__(self, template_length: int = 128):
        self.template_length = template_length
        
        # Generate sample biometric templates
        templates = self._generate_biometric_templates()
        
        # Model probability based on Hamming weight (more balanced templates are more common)
        probabilities = []
        for template in templates:
            hamming_weight = template.count('1')
            # Bell curve around 50% ones
            center = template_length // 2
            distance_from_center = abs(hamming_weight - center)
            prob = math.exp(-(distance_from_center**2) / (2 * (template_length/6)**2))
            probabilities.append(prob)
        
        super().__init__(templates, probabilities)
    
    def _generate_biometric_templates(self, count: int = 100) -> List[str]:
        """Generate sample biometric templates as binary strings"""
        templates = []
        for _ in range(count):
            template = ''.join(secrets.choice('01') for _ in range(self.template_length))
            templates.append(template)
        return templates

class HoneyEncryption:
    """
    Main Honey Encryption implementation
    Encrypts messages using DTEs to ensure all decryptions yield plausible plaintexts
    """
    
    def __init__(self, dte: DistributionTransformingEncoder):
        self.dte = dte
    
    def _derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = b'honey_encryption_salt'  # Fixed salt for demonstration
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, message: Any, password: str) -> bytes:
        """
        Honey Encrypt a message with given password
        1. Encode message to seed using DTE
        2. Derive key from password
        3. Encrypt seed with symmetric encryption
        """
        try:
            # Step 1: Encode message to seed
            seed = self.dte.encode(message)
            
            # Step 2: Derive key from password
            key = self._derive_key(password)
            fernet = Fernet(key)
            
            # Step 3: Encrypt seed
            seed_bytes = seed.to_bytes(4, byteorder='big')
            ciphertext = fernet.encrypt(seed_bytes)
            
            return ciphertext
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt(self, ciphertext: bytes, password: str) -> Any:
        """
        Honey Decrypt ciphertext with given password
        Always returns a plausible message, even with wrong password
        1. Derive key from password
        2. Decrypt to get seed (or pseudo-random bytes if wrong key)
        3. Decode seed to message using DTE
        """
        try:
            # Step 1: Derive key from password
            key = self._derive_key(password)
            fernet = Fernet(key)
            
            # Step 2: Decrypt to get seed
            try:
                seed_bytes = fernet.decrypt(ciphertext)
                seed = int.from_bytes(seed_bytes, byteorder='big')
            except:
                # If decryption fails (wrong key), generate pseudo-random seed
                # This maintains the honey encryption property
                hash_input = password.encode() + ciphertext
                seed_hash = hashlib.sha256(hash_input).digest()
                seed = int.from_bytes(seed_hash[:4], byteorder='big')
            
            # Step 3: Decode seed to message
            message = self.dte.decode(seed)
            
            return message
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

# Global instances
credit_card_dte = CreditCardDTE()
password_dte = PasswordDTE()
biometric_dte = BiometricDTE()

he_credit_card = HoneyEncryption(credit_card_dte)
he_password = HoneyEncryption(password_dte)
he_biometric = HoneyEncryption(biometric_dte)

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_endpoint():
    try:
        data = request.json
        message_type = data.get('type')
        message = data.get('message')
        password = data.get('password')
        
        if not all([message_type, message, password]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Select appropriate HE instance
        if message_type == 'credit_card':
            he_instance = he_credit_card
        elif message_type == 'password':
            he_instance = he_password
        elif message_type == 'biometric':
            he_instance = he_biometric
        else:
            return jsonify({'error': 'Invalid message type'}), 400
        
        # Encrypt message
        ciphertext = he_instance.encrypt(message, password)
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        
        return jsonify({
            'success': True,
            'ciphertext': ciphertext_b64,
            'message_type': message_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_endpoint():
    try:
        data = request.json
        message_type = data.get('type')
        ciphertext_b64 = data.get('ciphertext')
        password = data.get('password')
        
        if not all([message_type, ciphertext_b64, password]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Decode ciphertext
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Select appropriate HE instance
        if message_type == 'credit_card':
            he_instance = he_credit_card
        elif message_type == 'password':
            he_instance = he_password
        elif message_type == 'biometric':
            he_instance = he_biometric
        else:
            return jsonify({'error': 'Invalid message type'}), 400
        
        # Decrypt message (always returns plausible result)
        decrypted_message = he_instance.decrypt(ciphertext, password)
        
        return jsonify({
            'success': True,
            'decrypted_message': decrypted_message,
            'message_type': message_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/demo')
def demo():
    """Demonstrate honey encryption with multiple password attempts"""
    # Encrypt a credit card with known password
    original_message = "4532123456789012"  # Sample Visa card
    correct_password = "mysecretpass"
    
    ciphertext = he_credit_card.encrypt(original_message, correct_password)
    
    # Try decrypting with various passwords
    test_passwords = [
        correct_password,
        "wrongpass1",
        "wrongpass2", 
        "admin",
        "password123",
        "hackerattempt"
    ]
    
    results = []
    for pwd in test_passwords:
        decrypted = he_credit_card.decrypt(ciphertext, pwd)
        is_correct = pwd == correct_password
        results.append({
            'password': pwd,
            'decrypted': decrypted,
            'is_correct': is_correct
        })
    
    return jsonify({
        'original_message': original_message,
        'correct_password': correct_password,
        'results': results,
        'explanation': 'Notice how each wrong password produces a different but plausible credit card number!'
    })

@app.route('/analyze')
def analyze():
    """Analyze the distribution properties of the DTEs"""
    analysis = {}
    
    # Analyze credit card DTE
    cc_analysis = {
        'message_count': len(credit_card_dte.message_space),
        'visa_percentage': sum(1 for card in credit_card_dte.message_space if card.startswith('4')) / len(credit_card_dte.message_space) * 100,
        'mastercard_percentage': sum(1 for card in credit_card_dte.message_space if card.startswith('5')) / len(credit_card_dte.message_space) * 100,
        'sample_cards': credit_card_dte.message_space[:10]
    }
    
    # Analyze password DTE
    pwd_analysis = {
        'message_count': len(password_dte.message_space),
        'top_passwords': list(zip(password_dte.message_space[:10], password_dte.probabilities[:10])),
        'entropy_estimate': -sum(p * math.log2(p) for p in password_dte.probabilities if p > 0)
    }
    
    # Analyze biometric DTE
    bio_analysis = {
        'message_count': len(biometric_dte.message_space),
        'template_length': biometric_dte.template_length,
        'sample_templates': biometric_dte.message_space[:5]
    }
    
    analysis['credit_card'] = cc_analysis
    analysis['password'] = pwd_analysis  
    analysis['biometric'] = bio_analysis
    
    return jsonify(analysis)
