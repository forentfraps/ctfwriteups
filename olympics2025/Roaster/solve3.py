#!/usr/bin/env python3
"""
Backup File Decryptor for ASBP format
Based on IDA Pro analysis of httpd create_config_backup function
"""

import struct
import hashlib
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import argparse
import sys

class ASBPDecryptor:
    def __init__(self, hostname):
        self.hostname = hostname
        
    def decrypt_backup(self, backup_data):
        """
        Decrypt ASBP backup file
        
        Args:
            backup_data: Raw backup file bytes
            
        Returns:
            tuple: (success, decrypted_config_or_error_message)
        """
        try:
            # Parse header
            header = self.parse_header(backup_data)
            if not header:
                return False, "Invalid header format"
                
            # Generate AES key from hostname
            aes_key = self.generate_aes_key(self.hostname)
            
            # Construct IV from header data + constant
            iv = header['iv_data'] + struct.pack('>I', 0x41353135)
            
            # Decrypt payload
            decrypted_data = self.decrypt_payload(
                header['encrypted_payload'], 
                aes_key, 
                iv
            )
            with open("zlib_supposedly.bin", "wb") as f:
                f.write(decrypted_data)
            
            if not decrypted_data:
                return False, "Decryption failed"
                
            # Verify integrity - SHA-256 is of the encrypted payload, not decrypted
            if not self.verify_integrity(header['encrypted_payload'], header['sha256_hash']):
                return False, "Integrity check failed"
                
            # Decompress
            try:
                config_data = zlib.decompress(decrypted_data)
                return True, config_data.decode('utf-8', errors='ignore')
            except zlib.error as e:
                return False, f"Zlib decompression failed: {e}"
                
        except Exception as e:
            return False, f"Decryption error: {e}"
    
    def parse_header(self, data):
        """Parse ASBP header structure"""
        if len(data) < 58:
            return None
            
        # Check magic bytes (ASBP in little-endian)
        magic = struct.unpack('<I', data[0:4])[0]
        if magic != 0x50425341:  # "ASBP" as little-endian int
            return None
            
        header = {
            'magic': magic,
            'random_header': data[4:14],          # 10 bytes random data
            'iv_data': data[14:26],               # 12 bytes IV data  
            'sha256_hash': data[26:58],           # 32 bytes SHA-256
            'encrypted_payload': data[58:]        # Rest is encrypted payload
        }
        
        return header
    
    def generate_aes_key(self, hostname):
        """Generate AES key from hostname using SHA-256"""
        # Create the key string: "A:{hostname}:S"
        key_string = f"A:{hostname}:S"
        
        # SHA-256 hash and take first 16 bytes for AES-128
        sha256_hash = hashlib.sha256(key_string.encode('utf-8')).digest()
        aes_key = sha256_hash[:16]
        
        return aes_key
    
    def decrypt_payload(self, encrypted_data, key, iv):
        """Decrypt the payload using AES-128-CBC"""
        try:
            if len(encrypted_data) % 16 != 0:
                return None
                
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_data)
            
            # Remove PKCS7 padding
            try:
                unpadded = unpad(decrypted, 16)
                return unpadded
            except ValueError:
                # Try manual padding removal if unpad fails
                padding_length = decrypted[-1]
                if padding_length <= 16:
                    return decrypted[:-padding_length]
                return None
                
        except Exception:
            return None
    
    def verify_integrity(self, encrypted_payload, expected_hash):
        """Verify SHA-256 integrity of encrypted payload (not decrypted data)"""
        actual_hash = hashlib.sha256(encrypted_payload).digest()
        return actual_hash == expected_hash
    
    def analyze_header(self, backup_data):
        """Analyze and display header information"""
        if len(backup_data) < 58:
            print("File too small for valid ASBP header")
            return
            
        header = self.parse_header(backup_data)
        if not header:
            print("Invalid ASBP header")
            return
            
        print("=== ASBP Header Analysis ===")
        print(f"Magic: 0x{header['magic']:08x} ({'ASBP' if header['magic'] == 0x50425341 else 'INVALID'})")
        print(f"Random Header (10 bytes): {header['random_header'].hex()}")
        print(f"IV Data (12 bytes): {header['iv_data'].hex()}")
        print(f"SHA-256 Hash: {header['sha256_hash'].hex()}")
        print(f"Encrypted Payload Size: {len(header['encrypted_payload'])} bytes")
        
        # Show constructed IV
        full_iv = header['iv_data'] + struct.pack('>I', 0x41353135)
        print(f"Full IV (16 bytes): {full_iv.hex()}")
        
        # Show key generation
        key_string = f"A:{self.hostname}:S"
        aes_key = self.generate_aes_key(self.hostname)
        print(f"Key String: '{key_string}'")
        print(f"AES Key: {aes_key.hex()}")

def main():
    parser = argparse.ArgumentParser(description='Decrypt ASBP backup files')
    parser.add_argument('backup_file', help='Path to backup file')
    parser.add_argument('hostname', help='Device hostname for key generation')
    parser.add_argument('--analyze', action='store_true', help='Only analyze header, don\'t decrypt')
    parser.add_argument('--output', '-o', help='Output file for decrypted config')
    
    args = parser.parse_args()
    
    try:
        with open(args.backup_file, 'rb') as f:
            backup_data = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.backup_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    decryptor = ASBPDecryptor(args.hostname)
    
    if args.analyze:
        decryptor.analyze_header(backup_data)
        return
    
    print(f"Attempting to decrypt backup file with hostname: '{args.hostname}'")
    success, result = decryptor.decrypt_backup(backup_data)
    
    if success:
        print("✅ Decryption successful!")
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(result)
                print(f"Decrypted config saved to: {args.output}")
            except Exception as e:
                print(f"Error saving output: {e}")
        else:
            print("\n=== Decrypted Configuration ===")
            print(result)
    else:
        print(f"❌ Decryption failed: {result}")
        
        # Try analyzing header anyway
        print("\n=== Header Analysis ===")
        decryptor.analyze_header(backup_data)

if __name__ == "__main__":
    main()
