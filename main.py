#!/usr/bin/env python3
"""
数据加密与密码管理系统
主程序入口
"""
import os
import sys
from password_vault import PasswordVault
from file_encryptor import FileEncryptor
from crypto_manager import CryptoManager
from utils import (
    get_master_password, 
    confirm_password, 
    generate_password,
    clear_screen,
    print_header,
    copy_to_clipboard
)


class SecureVaultApp:
    """安全保险库应用"""
    
    def __init__(self):
        self.vault_path = "vault"
        self.master_password_file = os.path.join(self.vault_path, "master.hash")
        self.vault = PasswordVault(self.vault_path)
        self.file_enc = FileEncryptor()
        self.crypto = CryptoManager()
        self.master_password = None
    
    def initialize(self):
        """初始化应用"""
        os.makedirs(self.vault_path, exist_ok=True)
        
        # 检查是否首次使用
        if not os.path.exists(self.master_password_file):
            self.first_time_setup()
        else:
            self.login()
    
    def first_time_setup(self):
        """首次设置"""
        print_header("欢迎使用数据加密与密码管理系统")
        print("\n🔐 首次使用，请设置主密码")
        print("⚠️  主密码将用于保护所有数据，请妥善保管！")
        print("💡 建议：至少12位，包含大小写字母、数字和符号\n")
        
        password = confirm_password()
        
        # 保存主密码哈希
        password_hash = self.crypto.hash_password(password)
        with open(self.master_password_file, 'w') as f:
            f.write(password_hash)
        
        self.master_password = password
        print("\n✅ 主密码设置成功！")
        input("\n按回车键继续...")
    
    def login(self):
        """登录验证"""
        print_header("数据加密与密码管理系统")
        
        # 读取存储的密码哈希
        with open(self.master_password_file, 'r') as f:
            stored_hash = f.read().strip()
        
        # 验证密码（最多3次机会）
        for attempt in range(3):
            password = get_master_password()
            
            if self.crypto.verify_password(password, stored_hash):
                self.master_password = password
                print("\n✅ 登录成功！")
                return
            else:
                remaining = 2 - attempt
                if remaining > 0:
                    print(f"❌ 密码错误！还有 {remaining} 次机会")
                else:
                    print("❌ 密码错误次数过多，程序退出")
                    sys.exit(1)
    
    def main_menu(self):
        """主菜单"""
        while True:
            clear_screen()
            print_header("主菜单")
            print("\n1. 密码管理")
            print("2. 数据加密")
            print("3. 文件加密")
            print("4. 更改主密码")
            print("0. 退出")
            
            choice = input("\n请选择功能 [0-4]: ").strip()
            
            if choice == '1':
                self.password_menu()
            elif choice == '2':
                self.data_encryption_menu()
            elif choice == '3':
                self.file_encryption_menu()
            elif choice == '4':
                self.change_master_password()
            elif choice == '0':
                print("\n👋 再见！")
                sys.exit(0)
            else:
                print("❌ 无效选择")
                input("按回车键继续...")
    
    def password_menu(self):
        """密码管理菜单"""
        while True:
            clear_screen()
            print_header("密码管理")
            print("\n1. 添加新密码")
            print("2. 查看密码")
            print("3. 列出所有服务")
            print("4. 删除密码")
            print("5. 生成随机密码")
            print("0. 返回主菜单")
            
            choice = input("\n请选择操作 [0-5]: ").strip()
            
            if choice == '1':
                self.add_password()
            elif choice == '2':
                self.view_password()
            elif choice == '3':
                self.list_passwords()
            elif choice == '4':
                self.delete_password()
            elif choice == '5':
                self.generate_random_password()
            elif choice == '0':
                break
            else:
                print("❌ 无效选择")
                input("按回车键继续...")
    
    def add_password(self):
        """添加密码"""
        clear_screen()
        print_header("添加新密码")
        
        service = input("\n服务名称 (如: Gmail, GitHub): ").strip()
        if not service:
            print("❌ 服务名称不能为空")
            input("按回车键继续...")
            return
        
        username = input("用户名/邮箱: ").strip()
        
        print("\n选择密码输入方式:")
        print("1. 手动输入")
        print("2. 自动生成强密码")
        choice = input("请选择 [1-2]: ").strip()
        
        if choice == '2':
            password = generate_password()
            print(f"\n✨ 生成的密码: {password}")
            if copy_to_clipboard(password):
                print("✅ 密码已复制到剪贴板")
        else:
            password = get_master_password("请输入密码: ")
        
        notes = input("备注 (可选): ").strip()
        
        try:
            self.vault.add_password(
                self.master_password,
                service,
                username,
                password,
                notes
            )
            print(f"\n✅ 密码已保存到保险库: {service}")
        except Exception as e:
            print(f"\n❌ 保存失败: {e}")
        
        input("\n按回车键继续...")
    
    def view_password(self):
        """查看密码"""
        clear_screen()
        print_header("查看密码")
        
        service = input("\n请输入服务名称: ").strip()
        
        try:
            info = self.vault.get_password(self.master_password, service)
            if info:
                print(f"\n📋 服务: {service}")
                print(f"👤 用户名: {info['username']}")
                print(f"🔑 密码: {info['password']}")
                if info.get('notes'):
                    print(f"📝 备注: {info['notes']}")
                print(f"📅 创建时间: {info['created_at']}")
                
                if copy_to_clipboard(info['password']):
                    print("\n✅ 密码已复制到剪贴板")
            else:
                print(f"\n❌ 未找到服务: {service}")
        except Exception as e:
            print(f"\n❌ 获取失败: {e}")
        
        input("\n按回车键继续...")
    
    def list_passwords(self):
        """列出所有密码"""
        clear_screen()
        print_header("所有保存的服务")
        
        try:
            services = self.vault.list_services(self.master_password)
            if services:
                print(f"\n共有 {len(services)} 个服务:\n")
                for i, service in enumerate(services, 1):
                    print(f"{i}. {service}")
            else:
                print("\n📭 暂无保存的密码")
        except Exception as e:
            print(f"\n❌ 加载失败: {e}")
        
        input("\n按回车键继续...")
    
    def delete_password(self):
        """删除密码"""
        clear_screen()
        print_header("删除密码")
        
        service = input("\n请输入要删除的服务名称: ").strip()
        confirm = input(f"⚠️  确定要删除 '{service}' 吗? (yes/no): ").strip().lower()
        
        if confirm == 'yes':
            try:
                if self.vault.delete_password(self.master_password, service):
                    print(f"\n✅ 已删除: {service}")
                else:
                    print(f"\n❌ 未找到服务: {service}")
            except Exception as e:
                print(f"\n❌ 删除失败: {e}")
        else:
            print("\n❌ 已取消删除")
        
        input("\n按回车键继续...")
    
    def generate_random_password(self):
        """生成随机密码"""
        clear_screen()
        print_header("生成随机密码")
        
        try:
            length = int(input("\n密码长度 (默认16): ").strip() or "16")
            use_symbols = input("包含特殊符号? (y/n, 默认y): ").strip().lower() != 'n'
            
            password = generate_password(length, use_symbols)
            print(f"\n✨ 生成的密码: {password}")
            
            if copy_to_clipboard(password):
                print("✅ 密码已复制到剪贴板")
        except ValueError:
            print("❌ 无效的长度")
        
        input("\n按回车键继续...")
    
    def data_encryption_menu(self):
        """数据加密菜单"""
        while True:
            clear_screen()
            print_header("数据加密")
            print("\n1. 加密文本")
            print("2. 解密文本")
            print("0. 返回主菜单")
            
            choice = input("\n请选择操作 [0-2]: ").strip()
            
            if choice == '1':
                self.encrypt_text()
            elif choice == '2':
                self.decrypt_text()
            elif choice == '0':
                break
            else:
                print("❌ 无效选择")
                input("按回车键继续...")
    
    def encrypt_text(self):
        """加密文本"""
        clear_screen()
        print_header("加密文本")
        
        print("\n请输入要加密的文本 (输入空行结束):")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        
        text = '\n'.join(lines)
        if not text:
            print("❌ 文本不能为空")
            input("按回车键继续...")
            return
        
        try:
            encrypted = self.file_enc.encrypt_text(text, self.master_password)
            print("\n✅ 加密成功！加密数据:")
            print(encrypted)
            
            if copy_to_clipboard(encrypted):
                print("\n✅ 已复制到剪贴板")
        except Exception as e:
            print(f"\n❌ 加密失败: {e}")
        
        input("\n按回车键继续...")
    
    def decrypt_text(self):
        """解密文本"""
        clear_screen()
        print_header("解密文本")
        
        encrypted = input("\n请输入加密的文本: ").strip()
        
        try:
            decrypted = self.file_enc.decrypt_text(encrypted, self.master_password)
            print("\n✅ 解密成功！原始内容:")
            print(decrypted)
        except Exception as e:
            print(f"\n❌ 解密失败: {e}")
        
        input("\n按回车键继续...")
    
    def file_encryption_menu(self):
        """文件加密菜单"""
        while True:
            clear_screen()
            print_header("文件加密")
            print("\n1. 加密文件")
            print("2. 解密文件")
            print("0. 返回主菜单")
            
            choice = input("\n请选择操作 [0-2]: ").strip()
            
            if choice == '1':
                self.encrypt_file()
            elif choice == '2':
                self.decrypt_file()
            elif choice == '0':
                break
            else:
                print("❌ 无效选择")
                input("按回车键继续...")
    
    def encrypt_file(self):
        """加密文件"""
        clear_screen()
        print_header("加密文件")
        
        input_file = input("\n输入文件路径: ").strip()
        output_file = input("输出文件路径 (默认添加.enc): ").strip()
        
        if not output_file:
            output_file = input_file + ".enc"
        
        try:
            self.file_enc.encrypt_file(input_file, output_file, self.master_password)
            print(f"\n✅ 文件加密成功: {output_file}")
        except Exception as e:
            print(f"\n❌ 加密失败: {e}")
        
        input("\n按回车键继续...")
    
    def decrypt_file(self):
        """解密文件"""
        clear_screen()
        print_header("解密文件")
        
        input_file = input("\n加密文件路径: ").strip()
        output_file = input("输出文件路径 (默认删除.enc): ").strip()
        
        if not output_file:
            if input_file.endswith('.enc'):
                output_file = input_file[:-4]
            else:
                output_file = input_file + ".decrypted"
        
        try:
            self.file_enc.decrypt_file(input_file, output_file, self.master_password)
            print(f"\n✅ 文件解密成功: {output_file}")
        except Exception as e:
            print(f"\n❌ 解密失败: {e}")
        
        input("\n按回车键继续...")
    
    def change_master_password(self):
        """更改主密码"""
        clear_screen()
        print_header("更改主密码")
        
        print("\n⚠️  更改主密码将需要重新加密所有数据")
        confirm = input("确定要继续吗? (yes/no): ").strip().lower()
        
        if confirm != 'yes':
            print("❌ 已取消")
            input("按回车键继续...")
            return
        
        # 验证当前密码
        old_password = get_master_password("请输入当前主密码: ")
        with open(self.master_password_file, 'r') as f:
            stored_hash = f.read().strip()
        
        if not self.crypto.verify_password(old_password, stored_hash):
            print("❌ 当前密码错误")
            input("按回车键继续...")
            return
        
        # 设置新密码
        new_password = confirm_password()
        
        try:
            # 重新加密密码库
            if os.path.exists(self.vault.passwords_file):
                passwords = self.vault._load_passwords(old_password)
                self.vault._save_passwords(passwords, new_password)
            
            # 更新主密码哈希
            new_hash = self.crypto.hash_password(new_password)
            with open(self.master_password_file, 'w') as f:
                f.write(new_hash)
            
            self.master_password = new_password
            print("\n✅ 主密码更改成功！")
        except Exception as e:
            print(f"\n❌ 更改失败: {e}")
        
        input("\n按回车键继续...")
    
    def run(self):
        """运行应用"""
        try:
            self.initialize()
            self.main_menu()
        except KeyboardInterrupt:
            print("\n\n👋 程序已退出")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ 发生错误: {e}")
            sys.exit(1)


if __name__ == "__main__":
    app = SecureVaultApp()
    app.run()
