#!/usr/bin/env python3
"""
数据加密与密码管理系统 - Web界面
基于Flask的Web GUI，兼容性更好
"""
import os
import json
import secrets
from flask import Flask, render_template, request, jsonify, send_file, session
from werkzeug.utils import secure_filename
from password_vault import PasswordVault
from file_encryptor import FileEncryptor
from crypto_manager import CryptoManager
from utils import generate_password
import tempfile

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# 初始化组件
vault_path = "vault"
os.makedirs(vault_path, exist_ok=True)
master_password_file = os.path.join(vault_path, "master.hash")

vault = PasswordVault(vault_path)
file_enc = FileEncryptor()
crypto = CryptoManager()


def is_logged_in():
    """检查是否已登录"""
    return 'master_password' in session and session['master_password'] is not None


def get_master_password():
    """获取当前会话的主密码"""
    return session.get('master_password')


@app.route('/')
def index():
    """首页"""
    # 检查是否首次使用
    first_time = not os.path.exists(master_password_file)
    logged_in = is_logged_in()
    
    return render_template('index.html', first_time=first_time, logged_in=logged_in)


@app.route('/api/setup', methods=['POST'])
def setup_master_password():
    """设置主密码（首次使用）"""
    data = request.json
    password1 = data.get('password1')
    password2 = data.get('password2')
    
    if not password1 or not password2:
        return jsonify({'success': False, 'message': '密码不能为空'})
    
    if password1 != password2:
        return jsonify({'success': False, 'message': '两次密码输入不一致'})
    
    if len(password1) < 8:
        return jsonify({'success': False, 'message': '密码长度至少8位'})
    
    try:
        # 保存主密码哈希
        password_hash = crypto.hash_password(password1)
        with open(master_password_file, 'w') as f:
            f.write(password_hash)
        
        session['master_password'] = password1
        return jsonify({'success': True, 'message': '主密码设置成功'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'设置失败: {str(e)}'})


@app.route('/api/login', methods=['POST'])
def login():
    """登录验证"""
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({'success': False, 'message': '密码不能为空'})
    
    try:
        with open(master_password_file, 'r') as f:
            stored_hash = f.read().strip()
        
        if crypto.verify_password(password, stored_hash):
            session['master_password'] = password
            return jsonify({'success': True, 'message': '登录成功'})
        else:
            return jsonify({'success': False, 'message': '密码错误'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'登录失败: {str(e)}'})


@app.route('/api/logout', methods=['POST'])
def logout():
    """登出"""
    session.pop('master_password', None)
    return jsonify({'success': True, 'message': '已退出'})


@app.route('/api/passwords/list', methods=['GET'])
def list_passwords():
    """获取密码列表"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    try:
        passwords = vault.list_passwords(get_master_password())
        return jsonify({'success': True, 'passwords': passwords})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/passwords/add', methods=['POST'])
def add_password():
    """添加密码"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    data = request.json
    site = data.get('site', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    notes = data.get('notes', '').strip()
    
    if not site:
        return jsonify({'success': False, 'message': '网站/服务名称不能为空'})
    
    if not password:
        return jsonify({'success': False, 'message': '密码不能为空'})
    
    try:
        vault.add_password(site, username, password, get_master_password(), notes)
        return jsonify({'success': True, 'message': f'密码已保存: {site}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/passwords/get/<site>', methods=['GET'])
def get_password(site):
    """获取密码详情"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    try:
        password_data = vault.get_password(site, get_master_password())
        return jsonify({'success': True, 'data': password_data})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/passwords/delete/<site>', methods=['DELETE'])
def delete_password(site):
    """删除密码"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    try:
        vault.delete_password(site)
        return jsonify({'success': True, 'message': f'已删除密码: {site}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/passwords/generate', methods=['POST'])
def generate_password_api():
    """生成强密码"""
    data = request.json
    length = int(data.get('length', 16))
    
    if length < 8 or length > 32:
        return jsonify({'success': False, 'message': '密码长度应在8-32位之间'})
    
    try:
        password = generate_password(length)
        return jsonify({'success': True, 'password': password})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/text/encrypt', methods=['POST'])
def encrypt_text():
    """加密文本"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    data = request.json
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'success': False, 'message': '文本不能为空'})
    
    try:
        encrypted = crypto.encrypt(text.encode(), get_master_password())
        encrypted_b64 = encrypted.decode('utf-8')
        return jsonify({'success': True, 'encrypted': encrypted_b64})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/text/decrypt', methods=['POST'])
def decrypt_text():
    """解密文本"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    data = request.json
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'success': False, 'message': '文本不能为空'})
    
    try:
        decrypted = crypto.decrypt(text.encode(), get_master_password())
        decrypted_text = decrypted.decode('utf-8')
        return jsonify({'success': True, 'decrypted': decrypted_text})
    except Exception as e:
        return jsonify({'success': False, 'message': f'解密失败: {str(e)}'})


@app.route('/api/file/encrypt', methods=['POST'])
def encrypt_file():
    """加密文件"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '没有选择文件'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': '没有选择文件'})
    
    try:
        # 保存上传的文件
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)
        
        # 加密文件
        output_filename = filename + '.encrypted'
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        
        file_enc.encrypt_file(input_path, output_path, get_master_password())
        
        # 清理输入文件
        os.remove(input_path)
        
        return jsonify({
            'success': True, 
            'message': '文件加密成功',
            'download_url': f'/api/file/download/{output_filename}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'加密失败: {str(e)}'})


@app.route('/api/file/decrypt', methods=['POST'])
def decrypt_file():
    """解密文件"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '没有选择文件'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': '没有选择文件'})
    
    try:
        # 保存上传的文件
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)
        
        # 解密文件
        output_filename = filename.replace('.encrypted', '.decrypted')
        if output_filename == filename:
            output_filename = filename + '.decrypted'
        
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        
        file_enc.decrypt_file(input_path, output_path, get_master_password())
        
        # 清理输入文件
        os.remove(input_path)
        
        return jsonify({
            'success': True, 
            'message': '文件解密成功',
            'download_url': f'/api/file/download/{output_filename}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'解密失败: {str(e)}'})


@app.route('/api/file/download/<filename>')
def download_file(filename):
    """下载文件"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'message': '文件不存在'})
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/file/encrypt-local', methods=['POST'])
def encrypt_file_local():
    """加密本地文件（保存在原路径）"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    data = request.json
    input_path = data.get('input_path', '').strip()
    
    if not input_path:
        return jsonify({'success': False, 'message': '请指定文件路径'})
    
    # 扩展用户路径
    input_path = os.path.expanduser(input_path)
    
    if not os.path.exists(input_path):
        return jsonify({'success': False, 'message': '文件不存在'})
    
    if not os.path.isfile(input_path):
        return jsonify({'success': False, 'message': '不是有效的文件'})
    
    try:
        # 在同一目录下生成输出文件名
        output_path = input_path + '.encrypted'
        
        # 检查输出文件是否已存在
        if os.path.exists(output_path):
            return jsonify({'success': False, 'message': f'输出文件已存在: {output_path}'})
        
        # 加密文件
        file_enc.encrypt_file(input_path, output_path, get_master_password())
        
        return jsonify({
            'success': True, 
            'message': '文件加密成功',
            'output_path': output_path
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'加密失败: {str(e)}'})


@app.route('/api/file/decrypt-local', methods=['POST'])
def decrypt_file_local():
    """解密本地文件（保存在原路径）"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    data = request.json
    input_path = data.get('input_path', '').strip()
    
    if not input_path:
        return jsonify({'success': False, 'message': '请指定文件路径'})
    
    # 扩展用户路径
    input_path = os.path.expanduser(input_path)
    
    if not os.path.exists(input_path):
        return jsonify({'success': False, 'message': '文件不存在'})
    
    if not os.path.isfile(input_path):
        return jsonify({'success': False, 'message': '不是有效的文件'})
    
    try:
        # 在同一目录下生成输出文件名
        if input_path.endswith('.encrypted'):
            output_path = input_path[:-10]  # 移除 .encrypted
        else:
            output_path = input_path + '.decrypted'
        
        # 检查输出文件是否已存在
        if os.path.exists(output_path):
            return jsonify({'success': False, 'message': f'输出文件已存在: {output_path}'})
        
        # 解密文件
        file_enc.decrypt_file(input_path, output_path, get_master_password())
        
        return jsonify({
            'success': True, 
            'message': '文件解密成功',
            'output_path': output_path
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'解密失败: {str(e)}'})


@app.route('/api/change-password', methods=['POST'])
def change_master_password():
    """更改主密码"""
    if not is_logged_in():
        return jsonify({'success': False, 'message': '未登录'})
    
    data = request.json
    old_password = data.get('old_password')
    new_password1 = data.get('new_password1')
    new_password2 = data.get('new_password2')
    
    if old_password != get_master_password():
        return jsonify({'success': False, 'message': '当前密码错误'})
    
    if not new_password1:
        return jsonify({'success': False, 'message': '新密码不能为空'})
    
    if new_password1 != new_password2:
        return jsonify({'success': False, 'message': '两次输入的新密码不一致'})
    
    if len(new_password1) < 8:
        return jsonify({'success': False, 'message': '密码长度至少8位'})
    
    try:
        # 保存新密码哈希
        password_hash = crypto.hash_password(new_password1)
        with open(master_password_file, 'w') as f:
            f.write(password_hash)
        
        session['master_password'] = new_password1
        return jsonify({'success': True, 'message': '主密码已更改'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'更改失败: {str(e)}'})


if __name__ == '__main__':
    print("🔐 数据加密与密码管理系统 - Web界面")
    print("=" * 50)
    print("🌐 访问地址: http://127.0.0.1:5000")
    print("⚠️  仅本地访问，不对外开放")
    print("🛑 按 Ctrl+C 停止服务")
    print("=" * 50)
    app.run(debug=False, host='127.0.0.1', port=5000)
