"""
工具函数模块
"""
import os
import getpass
import secrets
import string


def get_master_password(prompt: str = "请输入主密码: ") -> str:
    """安全地获取主密码（不显示输入）"""
    return getpass.getpass(prompt)


def confirm_password() -> str:
    """确认密码（需要输入两次）"""
    while True:
        password1 = get_master_password("请设置主密码: ")
        password2 = get_master_password("请再次输入主密码: ")
        
        if password1 == password2:
            if len(password1) < 8:
                print("❌ 密码长度至少8位，请重新设置")
                continue
            return password1
        else:
            print("❌ 两次密码不一致，请重新输入")


def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    """
    生成随机强密码
    
    Args:
        length: 密码长度
        use_symbols: 是否包含特殊符号
        
    Returns:
        随机生成的强密码
    """
    characters = string.ascii_letters + string.digits
    if use_symbols:
        characters += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # 确保密码包含各种字符类型
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    
    if use_symbols:
        password.append(secrets.choice("!@#$%^&*()-_=+"))
    
    # 填充剩余长度
    password.extend(secrets.choice(characters) for _ in range(length - len(password)))
    
    # 打乱顺序
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)


def clear_screen():
    """清屏"""
    os.system('clear' if os.name != 'nt' else 'cls')


def print_header(title: str):
    """打印标题"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)


def copy_to_clipboard(text: str) -> bool:
    """
    复制文本到剪贴板
    
    Args:
        text: 要复制的文本
        
    Returns:
        是否成功复制
    """
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        return False
