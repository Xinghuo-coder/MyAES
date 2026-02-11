"""
文件加密模块
加密和解密文件
"""
import os
from crypto_manager import CryptoManager


class FileEncryptor:
    """文件加密器"""
    
    def __init__(self):
        self.crypto = CryptoManager()
    
    def encrypt_file(self, input_file: str, output_file: str, password: str):
        """
        加密文件
        
        Args:
            input_file: 输入文件路径
            output_file: 输出文件路径
            password: 加密密码
        """
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"文件不存在: {input_file}")
        
        # 读取文件内容
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # 加密
        encrypted_data = self.crypto.encrypt(data, password)
        
        # 写入加密文件
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
    
    def decrypt_file(self, input_file: str, output_file: str, password: str):
        """
        解密文件
        
        Args:
            input_file: 加密的输入文件路径
            output_file: 解密后的输出文件路径
            password: 解密密码
        """
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"文件不存在: {input_file}")
        
        # 读取加密文件
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        
        # 解密
        decrypted_data = self.crypto.decrypt(encrypted_data, password)
        
        # 写入解密文件
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
    
    def encrypt_text(self, text: str, password: str) -> str:
        """
        加密文本数据
        
        Args:
            text: 要加密的文本
            password: 加密密码
            
        Returns:
            加密后的Base64字符串
        """
        return self.crypto.encrypt_string(text, password)
    
    def decrypt_text(self, encrypted_text: str, password: str) -> str:
        """
        解密文本数据
        
        Args:
            encrypted_text: 加密的Base64字符串
            password: 解密密码
            
        Returns:
            解密后的原始文本
        """
        return self.crypto.decrypt_string(encrypted_text, password)
