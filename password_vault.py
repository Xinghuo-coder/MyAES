"""
密码保险库模块
管理多个账户密码的安全存储
"""
import json
import os
from typing import Dict, List, Optional
from crypto_manager import CryptoManager


class PasswordVault:
    """密码保险库"""
    
    def __init__(self, vault_path: str = "vault"):
        self.vault_path = vault_path
        self.passwords_file = os.path.join(vault_path, "passwords.enc")
        self.crypto = CryptoManager()
        
        # 确保vault目录存在
        os.makedirs(vault_path, exist_ok=True)
    
    def _load_passwords(self, master_password: str) -> Dict:
        """加载密码数据"""
        if not os.path.exists(self.passwords_file):
            return {}
        
        try:
            with open(self.passwords_file, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
            
            decrypted_json = self.crypto.decrypt_string(encrypted_data, master_password)
            return json.loads(decrypted_json)
        except Exception as e:
            raise Exception(f"加载密码失败: {str(e)}")
    
    def _save_passwords(self, passwords: Dict, master_password: str):
        """保存密码数据"""
        json_data = json.dumps(passwords, ensure_ascii=False, indent=2)
        encrypted_data = self.crypto.encrypt_string(json_data, master_password)
        
        with open(self.passwords_file, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)
    
    def add_password(self, master_password: str, service: str, username: str, password: str, notes: str = ""):
        """
        添加新密码
        
        Args:
            master_password: 主密码
            service: 服务名称（如：Gmail, GitHub等）
            username: 用户名或邮箱
            password: 密码
            notes: 备注信息
        """
        passwords = self._load_passwords(master_password)
        
        passwords[service] = {
            "username": username,
            "password": password,
            "notes": notes,
            "created_at": self._get_timestamp()
        }
        
        self._save_passwords(passwords, master_password)
    
    def get_password(self, master_password: str, service: str) -> Optional[Dict]:
        """
        获取密码
        
        Args:
            master_password: 主密码
            service: 服务名称
            
        Returns:
            密码信息字典或None
        """
        passwords = self._load_passwords(master_password)
        return passwords.get(service)
    
    def list_services(self, master_password: str) -> List[str]:
        """
        列出所有服务名称
        
        Args:
            master_password: 主密码
            
        Returns:
            服务名称列表
        """
        passwords = self._load_passwords(master_password)
        return sorted(passwords.keys())
    
    def delete_password(self, master_password: str, service: str) -> bool:
        """
        删除密码
        
        Args:
            master_password: 主密码
            service: 服务名称
            
        Returns:
            是否成功删除
        """
        passwords = self._load_passwords(master_password)
        
        if service in passwords:
            del passwords[service]
            self._save_passwords(passwords, master_password)
            return True
        return False
    
    def update_password(self, master_password: str, service: str, new_password: str):
        """
        更新密码
        
        Args:
            master_password: 主密码
            service: 服务名称
            new_password: 新密码
        """
        passwords = self._load_passwords(master_password)
        
        if service in passwords:
            passwords[service]["password"] = new_password
            passwords[service]["updated_at"] = self._get_timestamp()
            self._save_passwords(passwords, master_password)
        else:
            raise ValueError(f"服务 '{service}' 不存在")
    
    @staticmethod
    def _get_timestamp() -> str:
        """获取当前时间戳"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
