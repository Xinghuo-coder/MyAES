"""
加密核心模块
提供基于AES-256-GCM的加密和解密功能
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


class CryptoManager:
    """加密管理器"""
    
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=3,        # 迭代次数
            memory_cost=65536,  # 内存使用（64MB）
            parallelism=4,      # 并行度
            hash_len=32,        # 哈希长度
            salt_len=16         # 盐值长度
        )
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        从密码派生加密密钥
        
        Args:
            password: 主密码
            salt: 盐值
            
        Returns:
            32字节的加密密钥
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,  # NIST 2023推荐值
        )
        return kdf.derive(password.encode())
    
    def hash_password(self, password: str) -> str:
        """
        哈希密码用于验证（使用Argon2）
        
        Args:
            password: 要哈希的密码
            
        Returns:
            密码哈希字符串
        """
        return self.ph.hash(password)
    
    def verify_password(self, password: str, hash_value: str) -> bool:
        """
        验证密码
        
        Args:
            password: 要验证的密码
            hash_value: 存储的哈希值
            
        Returns:
            验证是否成功
        """
        try:
            self.ph.verify(hash_value, password)
            # 如果需要重新哈希（参数已更新）
            if self.ph.check_needs_rehash(hash_value):
                return True  # 可以在这里重新哈希
            return True
        except VerifyMismatchError:
            return False
    
    def encrypt(self, data: bytes, password: str) -> bytes:
        """
        加密数据
        
        Args:
            data: 要加密的数据
            password: 加密密码
            
        Returns:
            加密后的数据（包含盐值和nonce）
        """
        # 生成随机盐值
        salt = os.urandom(16)
        
        # 派生密钥
        key = self.derive_key(password, salt)
        
        # 创建AES-GCM加密器
        aesgcm = AESGCM(key)
        
        # 生成随机nonce（12字节用于GCM）
        nonce = os.urandom(12)
        
        # 加密数据
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # 组合：盐值(16) + nonce(12) + 密文
        return salt + nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes, password: str) -> bytes:
        """
        解密数据
        
        Args:
            encrypted_data: 加密的数据
            password: 解密密码
            
        Returns:
            解密后的原始数据
            
        Raises:
            Exception: 解密失败（密码错误或数据损坏）
        """
        # 提取盐值、nonce和密文
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        
        # 派生密钥
        key = self.derive_key(password, salt)
        
        # 创建AES-GCM解密器
        aesgcm = AESGCM(key)
        
        try:
            # 解密数据
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise Exception("解密失败：密码错误或数据已损坏") from e
    
    def encrypt_string(self, text: str, password: str) -> str:
        """
        加密字符串
        
        Args:
            text: 要加密的文本
            password: 加密密码
            
        Returns:
            Base64编码的加密字符串
        """
        encrypted = self.encrypt(text.encode('utf-8'), password)
        return base64.b64encode(encrypted).decode('ascii')
    
    def decrypt_string(self, encrypted_text: str, password: str) -> str:
        """
        解密字符串
        
        Args:
            encrypted_text: Base64编码的加密文本
            password: 解密密码
            
        Returns:
            解密后的原始文本
        """
        encrypted = base64.b64decode(encrypted_text.encode('ascii'))
        decrypted = self.decrypt(encrypted, password)
        return decrypted.decode('utf-8')
