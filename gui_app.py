#!/usr/bin/env python3
"""
数据加密与密码管理系统 - 图形界面
提供友好的GUI操作界面
"""
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from password_vault import PasswordVault
from file_encryptor import FileEncryptor
from crypto_manager import CryptoManager
from utils import generate_password
import threading


class EncryptionGUI:
    """加密系统图形界面"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("数据加密与密码管理系统")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # 初始化组件
        self.vault_path = "vault"
        os.makedirs(self.vault_path, exist_ok=True)
        self.master_password_file = os.path.join(self.vault_path, "master.hash")
        
        self.vault = PasswordVault(self.vault_path)
        self.file_enc = FileEncryptor()
        self.crypto = CryptoManager()
        self.master_password = None
        
        # 设置样式
        self.setup_styles()
        
        # 检查是否首次使用
        if not os.path.exists(self.master_password_file):
            self.show_first_setup()
        else:
            self.show_login()
    
    def setup_styles(self):
        """设置UI样式"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # 配置颜色
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#2c3e50')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'), foreground='#34495e')
        style.configure('Info.TLabel', font=('Arial', 10), foreground='#7f8c8d')
        style.configure('Success.TLabel', font=('Arial', 10), foreground='#27ae60')
        style.configure('Error.TLabel', font=('Arial', 10), foreground='#e74c3c')
        
        style.configure('TButton', font=('Arial', 10), padding=6)
        style.configure('Primary.TButton', font=('Arial', 10, 'bold'))
    
    def clear_window(self):
        """清空窗口内容"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_first_setup(self):
        """首次设置界面"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="40")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title = ttk.Label(frame, text="🔐 欢迎使用数据加密与密码管理系统", style='Title.TLabel')
        title.pack(pady=20)
        
        # 说明
        info_text = """
        首次使用，请设置主密码
        
        ⚠️  主密码将用于保护所有数据，请妥善保管！
        💡 建议：至少12位，包含大小写字母、数字和符号
        """
        info = ttk.Label(frame, text=info_text, style='Info.TLabel', justify=tk.LEFT)
        info.pack(pady=10)
        
        # 密码输入
        ttk.Label(frame, text="设置主密码:", style='Header.TLabel').pack(pady=(20, 5))
        password1_entry = ttk.Entry(frame, show="*", width=40, font=('Arial', 11))
        password1_entry.pack(pady=5)
        
        ttk.Label(frame, text="确认主密码:", style='Header.TLabel').pack(pady=(10, 5))
        password2_entry = ttk.Entry(frame, show="*", width=40, font=('Arial', 11))
        password2_entry.pack(pady=5)
        
        # 错误提示标签
        error_label = ttk.Label(frame, text="", style='Error.TLabel')
        error_label.pack(pady=5)
        
        def setup_password():
            password1 = password1_entry.get()
            password2 = password2_entry.get()
            
            if not password1:
                error_label.config(text="❌ 密码不能为空")
                return
            
            if password1 != password2:
                error_label.config(text="❌ 两次密码输入不一致")
                return
            
            if len(password1) < 8:
                error_label.config(text="❌ 密码长度至少8位")
                return
            
            # 保存主密码哈希
            password_hash = self.crypto.hash_password(password1)
            with open(self.master_password_file, 'w') as f:
                f.write(password_hash)
            
            self.master_password = password1
            messagebox.showinfo("成功", "✅ 主密码设置成功！")
            self.show_main_window()
        
        # 按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="确认设置", command=setup_password, 
                  style='Primary.TButton', width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="退出", command=self.root.quit, width=15).pack(side=tk.LEFT, padx=5)
    
    def show_login(self):
        """登录界面"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="40")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title = ttk.Label(frame, text="🔐 数据加密与密码管理系统", style='Title.TLabel')
        title.pack(pady=40)
        
        # 密码输入
        ttk.Label(frame, text="请输入主密码:", style='Header.TLabel').pack(pady=(20, 5))
        password_entry = ttk.Entry(frame, show="*", width=40, font=('Arial', 11))
        password_entry.pack(pady=5)
        password_entry.focus()
        
        # 错误提示
        error_label = ttk.Label(frame, text="", style='Error.TLabel')
        error_label.pack(pady=5)
        
        # 读取存储的密码哈希
        with open(self.master_password_file, 'r') as f:
            stored_hash = f.read().strip()
        
        attempt_count = [0]  # 使用列表来在闭包中修改值
        
        def verify_password():
            password = password_entry.get()
            
            if self.crypto.verify_password(password, stored_hash):
                self.master_password = password
                self.show_main_window()
            else:
                attempt_count[0] += 1
                remaining = 3 - attempt_count[0]
                
                if remaining > 0:
                    error_label.config(text=f"❌ 密码错误！还有 {remaining} 次机会")
                    password_entry.delete(0, tk.END)
                else:
                    messagebox.showerror("错误", "密码错误次数过多，程序将退出")
                    self.root.quit()
        
        def on_enter(event):
            verify_password()
        
        password_entry.bind('<Return>', on_enter)
        
        # 按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="登录", command=verify_password, 
                  style='Primary.TButton', width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="退出", command=self.root.quit, width=15).pack(side=tk.LEFT, padx=5)
    
    def show_main_window(self):
        """主窗口"""
        self.clear_window()
        
        # 创建菜单栏
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 功能菜单
        function_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="功能", menu=function_menu)
        function_menu.add_command(label="密码管理", command=self.show_password_manager)
        function_menu.add_command(label="文件加密", command=self.show_file_encryption)
        function_menu.add_command(label="文本加密", command=self.show_text_encryption)
        function_menu.add_separator()
        function_menu.add_command(label="退出", command=self.root.quit)
        
        # 设置菜单
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="设置", menu=settings_menu)
        settings_menu.add_command(label="更改主密码", command=self.change_master_password)
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)
        
        # 创建notebook标签页
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 默认显示文件加密页面
        self.show_file_encryption()
    
    def show_password_manager(self):
        """密码管理界面"""
        # 清除所有标签页
        for tab in self.notebook.tabs():
            self.notebook.forget(tab)
        
        # 创建密码管理标签页
        password_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(password_frame, text="密码管理")
        
        # 左侧：密码列表
        left_frame = ttk.Frame(password_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        ttk.Label(left_frame, text="已保存的密码", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # 密码列表
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.password_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, 
                                          font=('Arial', 10), height=15)
        self.password_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.password_listbox.yview)
        
        # 按钮
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(pady=10, fill=tk.X)
        
        ttk.Button(btn_frame, text="查看密码", command=self.view_password, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="复制密码", command=self.copy_password, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除密码", command=self.delete_password, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="刷新列表", command=self.refresh_password_list, width=12).pack(side=tk.LEFT, padx=2)
        
        # 右侧：添加新密码
        right_frame = ttk.Frame(password_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))
        
        ttk.Label(right_frame, text="添加新密码", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # 网站名称
        ttk.Label(right_frame, text="网站/服务名称:").pack(anchor=tk.W, pady=(5, 2))
        self.site_entry = ttk.Entry(right_frame, width=30, font=('Arial', 10))
        self.site_entry.pack(fill=tk.X, pady=(0, 10))
        
        # 用户名
        ttk.Label(right_frame, text="用户名:").pack(anchor=tk.W, pady=(5, 2))
        self.username_entry = ttk.Entry(right_frame, width=30, font=('Arial', 10))
        self.username_entry.pack(fill=tk.X, pady=(0, 10))
        
        # 密码
        ttk.Label(right_frame, text="密码:").pack(anchor=tk.W, pady=(5, 2))
        self.new_password_entry = ttk.Entry(right_frame, width=30, font=('Arial', 10), show="*")
        self.new_password_entry.pack(fill=tk.X, pady=(0, 5))
        
        # 生成密码按钮
        gen_frame = ttk.Frame(right_frame)
        gen_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(gen_frame, text="生成强密码", command=self.generate_strong_password, width=15).pack(side=tk.LEFT)
        
        self.password_length = tk.IntVar(value=16)
        ttk.Label(gen_frame, text="长度:").pack(side=tk.LEFT, padx=(10, 2))
        ttk.Spinbox(gen_frame, from_=8, to=32, textvariable=self.password_length, width=5).pack(side=tk.LEFT)
        
        # 备注
        ttk.Label(right_frame, text="备注 (可选):").pack(anchor=tk.W, pady=(5, 2))
        self.notes_text = scrolledtext.ScrolledText(right_frame, width=30, height=4, font=('Arial', 9))
        self.notes_text.pack(fill=tk.BOTH, pady=(0, 10))
        
        # 添加按钮
        ttk.Button(right_frame, text="保存密码", command=self.save_password, 
                  style='Primary.TButton', width=20).pack(pady=10)
        
        # 加载密码列表
        self.refresh_password_list()
    
    def refresh_password_list(self):
        """刷新密码列表"""
        self.password_listbox.delete(0, tk.END)
        passwords = self.vault.list_passwords(self.master_password)
        for site in passwords:
            self.password_listbox.insert(tk.END, site)
    
    def save_password(self):
        """保存新密码"""
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.new_password_entry.get()
        notes = self.notes_text.get("1.0", tk.END).strip()
        
        if not site:
            messagebox.showwarning("警告", "请输入网站/服务名称")
            return
        
        if not password:
            messagebox.showwarning("警告", "请输入密码")
            return
        
        try:
            self.vault.add_password(site, username, password, self.master_password, notes)
            messagebox.showinfo("成功", f"✅ 密码已保存: {site}")
            
            # 清空输入框
            self.site_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.new_password_entry.delete(0, tk.END)
            self.notes_text.delete("1.0", tk.END)
            
            # 刷新列表
            self.refresh_password_list()
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}")
    
    def generate_strong_password(self):
        """生成强密码"""
        length = self.password_length.get()
        password = generate_password(length)
        self.new_password_entry.delete(0, tk.END)
        self.new_password_entry.insert(0, password)
        messagebox.showinfo("提示", f"已生成{length}位强密码")
    
    def view_password(self):
        """查看密码"""
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个密码项")
            return
        
        site = self.password_listbox.get(selection[0])
        
        try:
            password_data = self.vault.get_password(site, self.master_password)
            
            info = f"""
网站/服务: {password_data['site']}
用户名: {password_data['username']}
密码: {password_data['password']}
"""
            if password_data.get('notes'):
                info += f"备注: {password_data['notes']}\n"
            
            messagebox.showinfo("密码详情", info)
        except Exception as e:
            messagebox.showerror("错误", f"获取密码失败: {str(e)}")
    
    def copy_password(self):
        """复制密码到剪贴板"""
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个密码项")
            return
        
        site = self.password_listbox.get(selection[0])
        
        try:
            password_data = self.vault.get_password(site, self.master_password)
            
            import pyperclip
            pyperclip.copy(password_data['password'])
            messagebox.showinfo("成功", f"✅ 密码已复制到剪贴板")
        except Exception as e:
            messagebox.showerror("错误", f"复制失败: {str(e)}")
    
    def delete_password(self):
        """删除密码"""
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个密码项")
            return
        
        site = self.password_listbox.get(selection[0])
        
        if messagebox.askyesno("确认删除", f"确定要删除 '{site}' 的密码吗？"):
            try:
                self.vault.delete_password(site)
                messagebox.showinfo("成功", f"✅ 已删除密码: {site}")
                self.refresh_password_list()
            except Exception as e:
                messagebox.showerror("错误", f"删除失败: {str(e)}")
    
    def show_file_encryption(self):
        """文件加密界面"""
        # 清除所有标签页
        for tab in self.notebook.tabs():
            self.notebook.forget(tab)
        
        # 创建文件加密标签页
        file_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(file_frame, text="文件加密/解密")
        
        # 加密区域
        encrypt_frame = ttk.LabelFrame(file_frame, text="📁 加密文件", padding="15")
        encrypt_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 输入文件
        ttk.Label(encrypt_frame, text="选择要加密的文件:", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        input_frame = ttk.Frame(encrypt_frame)
        input_frame.grid(row=1, column=0, sticky=tk.EW, pady=(0, 15))
        
        self.encrypt_input_entry = ttk.Entry(input_frame, width=50, font=('Arial', 10))
        self.encrypt_input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(input_frame, text="浏览...", command=self.browse_encrypt_input, width=10).pack(side=tk.LEFT)
        
        # 输出文件
        ttk.Label(encrypt_frame, text="加密后保存为:", style='Header.TLabel').grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        
        output_frame = ttk.Frame(encrypt_frame)
        output_frame.grid(row=3, column=0, sticky=tk.EW, pady=(0, 15))
        
        self.encrypt_output_entry = ttk.Entry(output_frame, width=50, font=('Arial', 10))
        self.encrypt_output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(output_frame, text="浏览...", command=self.browse_encrypt_output, width=10).pack(side=tk.LEFT)
        
        # 加密按钮
        ttk.Button(encrypt_frame, text="🔒 开始加密", command=self.encrypt_file_action, 
                  style='Primary.TButton', width=20).grid(row=4, column=0, pady=10)
        
        # 解密区域
        decrypt_frame = ttk.LabelFrame(file_frame, text="🔓 解密文件", padding="15")
        decrypt_frame.pack(fill=tk.BOTH, expand=True)
        
        # 输入文件
        ttk.Label(decrypt_frame, text="选择要解密的文件:", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        input_frame2 = ttk.Frame(decrypt_frame)
        input_frame2.grid(row=1, column=0, sticky=tk.EW, pady=(0, 15))
        
        self.decrypt_input_entry = ttk.Entry(input_frame2, width=50, font=('Arial', 10))
        self.decrypt_input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(input_frame2, text="浏览...", command=self.browse_decrypt_input, width=10).pack(side=tk.LEFT)
        
        # 输出文件
        ttk.Label(decrypt_frame, text="解密后保存为:", style='Header.TLabel').grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        
        output_frame2 = ttk.Frame(decrypt_frame)
        output_frame2.grid(row=3, column=0, sticky=tk.EW, pady=(0, 15))
        
        self.decrypt_output_entry = ttk.Entry(output_frame2, width=50, font=('Arial', 10))
        self.decrypt_output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(output_frame2, text="浏览...", command=self.browse_decrypt_output, width=10).pack(side=tk.LEFT)
        
        # 解密按钮
        ttk.Button(decrypt_frame, text="🔓 开始解密", command=self.decrypt_file_action, 
                  style='Primary.TButton', width=20).grid(row=4, column=0, pady=10)
        
        # 配置网格列权重
        encrypt_frame.columnconfigure(0, weight=1)
        decrypt_frame.columnconfigure(0, weight=1)
    
    def browse_encrypt_input(self):
        """选择要加密的文件"""
        filename = filedialog.askopenfilename(
            title="选择要加密的文件",
            filetypes=[("所有文件", "*.*")]
        )
        if filename:
            self.encrypt_input_entry.delete(0, tk.END)
            self.encrypt_input_entry.insert(0, filename)
            
            # 自动设置输出文件名
            if not self.encrypt_output_entry.get():
                self.encrypt_output_entry.delete(0, tk.END)
                self.encrypt_output_entry.insert(0, filename + ".encrypted")
    
    def browse_encrypt_output(self):
        """选择加密后的保存位置"""
        filename = filedialog.asksaveasfilename(
            title="保存加密文件",
            defaultextension=".encrypted",
            filetypes=[("加密文件", "*.encrypted"), ("所有文件", "*.*")]
        )
        if filename:
            self.encrypt_output_entry.delete(0, tk.END)
            self.encrypt_output_entry.insert(0, filename)
    
    def browse_decrypt_input(self):
        """选择要解密的文件"""
        filename = filedialog.askopenfilename(
            title="选择要解密的文件",
            filetypes=[("加密文件", "*.encrypted"), ("所有文件", "*.*")]
        )
        if filename:
            self.decrypt_input_entry.delete(0, tk.END)
            self.decrypt_input_entry.insert(0, filename)
            
            # 自动设置输出文件名
            if not self.decrypt_output_entry.get():
                output = filename.replace('.encrypted', '.decrypted')
                if output == filename:
                    output = filename + ".decrypted"
                self.decrypt_output_entry.delete(0, tk.END)
                self.decrypt_output_entry.insert(0, output)
    
    def browse_decrypt_output(self):
        """选择解密后的保存位置"""
        filename = filedialog.asksaveasfilename(
            title="保存解密文件",
            filetypes=[("所有文件", "*.*")]
        )
        if filename:
            self.decrypt_output_entry.delete(0, tk.END)
            self.decrypt_output_entry.insert(0, filename)
    
    def encrypt_file_action(self):
        """执行文件加密"""
        input_file = self.encrypt_input_entry.get()
        output_file = self.encrypt_output_entry.get()
        
        if not input_file or not output_file:
            messagebox.showwarning("警告", "请选择输入和输出文件")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("错误", "输入文件不存在")
            return
        
        # 在后台线程中执行加密
        def encrypt_thread():
            try:
                self.file_enc.encrypt_file(input_file, output_file, self.master_password)
                self.root.after(0, lambda: messagebox.showinfo("成功", f"✅ 文件加密成功！\n保存位置: {output_file}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("错误", f"加密失败: {str(e)}"))
        
        threading.Thread(target=encrypt_thread, daemon=True).start()
        messagebox.showinfo("提示", "正在加密文件，请稍候...")
    
    def decrypt_file_action(self):
        """执行文件解密"""
        input_file = self.decrypt_input_entry.get()
        output_file = self.decrypt_output_entry.get()
        
        if not input_file or not output_file:
            messagebox.showwarning("警告", "请选择输入和输出文件")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("错误", "输入文件不存在")
            return
        
        # 在后台线程中执行解密
        def decrypt_thread():
            try:
                self.file_enc.decrypt_file(input_file, output_file, self.master_password)
                self.root.after(0, lambda: messagebox.showinfo("成功", f"✅ 文件解密成功！\n保存位置: {output_file}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("错误", f"解密失败: {str(e)}"))
        
        threading.Thread(target=decrypt_thread, daemon=True).start()
        messagebox.showinfo("提示", "正在解密文件，请稍候...")
    
    def show_text_encryption(self):
        """文本加密界面"""
        # 清除所有标签页
        for tab in self.notebook.tabs():
            self.notebook.forget(tab)
        
        # 创建文本加密标签页
        text_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(text_frame, text="文本加密/解密")
        
        # 加密区域
        encrypt_frame = ttk.LabelFrame(text_frame, text="🔒 加密文本", padding="15")
        encrypt_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        ttk.Label(encrypt_frame, text="输入要加密的文本:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 5))
        
        self.text_encrypt_input = scrolledtext.ScrolledText(encrypt_frame, width=70, height=8, font=('Arial', 10))
        self.text_encrypt_input.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        ttk.Button(encrypt_frame, text="🔒 加密文本", command=self.encrypt_text_action, 
                  style='Primary.TButton', width=15).pack()
        
        ttk.Label(encrypt_frame, text="加密结果:", style='Header.TLabel').pack(anchor=tk.W, pady=(15, 5))
        
        self.text_encrypt_output = scrolledtext.ScrolledText(encrypt_frame, width=70, height=8, font=('Courier', 9))
        self.text_encrypt_output.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        btn_frame = ttk.Frame(encrypt_frame)
        btn_frame.pack()
        ttk.Button(btn_frame, text="复制结果", command=lambda: self.copy_text(self.text_encrypt_output), 
                  width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="清空", command=lambda: self.clear_text_areas(True), 
                  width=12).pack(side=tk.LEFT, padx=2)
        
        # 解密区域
        decrypt_frame = ttk.LabelFrame(text_frame, text="🔓 解密文本", padding="15")
        decrypt_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(decrypt_frame, text="输入要解密的文本:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 5))
        
        self.text_decrypt_input = scrolledtext.ScrolledText(decrypt_frame, width=70, height=8, font=('Courier', 9))
        self.text_decrypt_input.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        ttk.Button(decrypt_frame, text="🔓 解密文本", command=self.decrypt_text_action, 
                  style='Primary.TButton', width=15).pack()
        
        ttk.Label(decrypt_frame, text="解密结果:", style='Header.TLabel').pack(anchor=tk.W, pady=(15, 5))
        
        self.text_decrypt_output = scrolledtext.ScrolledText(decrypt_frame, width=70, height=8, font=('Arial', 10))
        self.text_decrypt_output.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        btn_frame2 = ttk.Frame(decrypt_frame)
        btn_frame2.pack()
        ttk.Button(btn_frame2, text="复制结果", command=lambda: self.copy_text(self.text_decrypt_output), 
                  width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame2, text="清空", command=lambda: self.clear_text_areas(False), 
                  width=12).pack(side=tk.LEFT, padx=2)
    
    def encrypt_text_action(self):
        """加密文本"""
        text = self.text_encrypt_input.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("警告", "请输入要加密的文本")
            return
        
        try:
            encrypted = self.crypto.encrypt(text.encode(), self.master_password)
            encrypted_b64 = encrypted.decode('utf-8')
            
            self.text_encrypt_output.delete("1.0", tk.END)
            self.text_encrypt_output.insert("1.0", encrypted_b64)
            
            messagebox.showinfo("成功", "✅ 文本加密成功")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
    
    def decrypt_text_action(self):
        """解密文本"""
        text = self.text_decrypt_input.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("警告", "请输入要解密的文本")
            return
        
        try:
            decrypted = self.crypto.decrypt(text.encode(), self.master_password)
            decrypted_text = decrypted.decode('utf-8')
            
            self.text_decrypt_output.delete("1.0", tk.END)
            self.text_decrypt_output.insert("1.0", decrypted_text)
            
            messagebox.showinfo("成功", "✅ 文本解密成功")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
    
    def copy_text(self, text_widget):
        """复制文本到剪贴板"""
        text = text_widget.get("1.0", tk.END).strip()
        if text:
            import pyperclip
            pyperclip.copy(text)
            messagebox.showinfo("成功", "✅ 已复制到剪贴板")
        else:
            messagebox.showwarning("警告", "没有可复制的内容")
    
    def clear_text_areas(self, is_encrypt):
        """清空文本区域"""
        if is_encrypt:
            self.text_encrypt_input.delete("1.0", tk.END)
            self.text_encrypt_output.delete("1.0", tk.END)
        else:
            self.text_decrypt_input.delete("1.0", tk.END)
            self.text_decrypt_output.delete("1.0", tk.END)
    
    def change_master_password(self):
        """更改主密码"""
        dialog = tk.Toplevel(self.root)
        dialog.title("更改主密码")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="更改主密码", style='Title.TLabel').pack(pady=(0, 20))
        
        ttk.Label(frame, text="当前密码:").pack(anchor=tk.W, pady=(5, 2))
        old_password_entry = ttk.Entry(frame, show="*", width=30)
        old_password_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(frame, text="新密码:").pack(anchor=tk.W, pady=(5, 2))
        new_password1_entry = ttk.Entry(frame, show="*", width=30)
        new_password1_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(frame, text="确认新密码:").pack(anchor=tk.W, pady=(5, 2))
        new_password2_entry = ttk.Entry(frame, show="*", width=30)
        new_password2_entry.pack(fill=tk.X, pady=(0, 10))
        
        def confirm_change():
            old_password = old_password_entry.get()
            new_password1 = new_password1_entry.get()
            new_password2 = new_password2_entry.get()
            
            if old_password != self.master_password:
                messagebox.showerror("错误", "当前密码错误", parent=dialog)
                return
            
            if not new_password1:
                messagebox.showwarning("警告", "新密码不能为空", parent=dialog)
                return
            
            if new_password1 != new_password2:
                messagebox.showerror("错误", "两次输入的新密码不一致", parent=dialog)
                return
            
            if len(new_password1) < 8:
                messagebox.showwarning("警告", "密码长度至少8位", parent=dialog)
                return
            
            try:
                # 保存新密码哈希
                password_hash = self.crypto.hash_password(new_password1)
                with open(self.master_password_file, 'w') as f:
                    f.write(password_hash)
                
                self.master_password = new_password1
                messagebox.showinfo("成功", "✅ 主密码已更改", parent=dialog)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("错误", f"更改失败: {str(e)}", parent=dialog)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="确认更改", command=confirm_change, 
                  style='Primary.TButton', width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy, width=12).pack(side=tk.LEFT, padx=5)
    
    def show_about(self):
        """显示关于信息"""
        about_text = """
数据加密与密码管理系统
版本: 1.0

一个安全的本地数据加密和密码管理工具

功能特性:
• AES-256-GCM 军事级加密
• Argon2 密钥派生
• 密码安全存储管理
• 文件和文本加密

⚠️ 注意: 请妥善保管主密码，
遗失将无法恢复数据
        """
        messagebox.showinfo("关于", about_text)


def main():
    """主程序入口"""
    root = tk.Tk()
    app = EncryptionGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
