from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for
import jwt
import sqlite3
import os
import hashlib
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# JWT配置
JWT_SECRET = os.urandom(32)  # 故意设置弱密钥
JWT_ALGORITHM = "HS256"

# 从环境变量获取FLAG
FLAG = os.getenv('GZCTF_FLAG', 'flag{test_flag}')

# 数据库初始化
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 删除现有表（如果存在）
    cursor.execute('DROP TABLE IF EXISTS system_info')
    cursor.execute('DROP TABLE IF EXISTS users')

    # 创建用户表
    cursor.execute('''
        CREATE TABLE users (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(100) NOT NULL,
            role VARCHAR(20) DEFAULT 'user',
            department VARCHAR(50),
            email VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 创建系统信息表
    cursor.execute('''
        CREATE TABLE system_info (
            uid INTEGER,
            info_type VARCHAR(50),
            content TEXT,
            is_sensitive BOOLEAN DEFAULT 0,
            FOREIGN KEY (uid) REFERENCES users (uid)
        )
    ''')

    # 插入测试用户数据
    test_users = [
        (0, 'admin', hashlib.md5(os.urandom(32)).hexdigest(), 'admin', '管理部', 'admin@company.com'),
        (1, 'manager1', hashlib.md5(os.urandom(32)).hexdigest(), 'user', '财务部', 'user1@company.com'),
        (2, 'manager2', hashlib.md5(os.urandom(32)).hexdigest(), 'user', '人事部', 'user2@company.com'),
        (3, 'user1', hashlib.md5(os.urandom(32)).hexdigest(), 'manager', '运营部', 'manager@company.com'),
        (4, 'user2', hashlib.md5(os.urandom(32)).hexdigest(), 'guest', '访客', 'guest@company.com')
    ]

    cursor.executemany('''
        INSERT OR REPLACE INTO users (uid, username, password, role, department, email)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', test_users)

    # 插入系统信息
    system_data = [
        (0, 'baseinfo', '管理员账户，拥有系统最高权限', 0),
        (0, 'privilege', '系统管理权限：用户管理、系统配置、日志审计', 1),
        (0, 'secret', FLAG, 1),
        (1, 'baseinfo', '普通用户，可查看基础信息', 0),
        (1, 'privilege', '基础访问权限：个人信息查看、密码修改', 1),
        (2, 'baseinfo', '人事部员工，负责招聘工作', 0),
        (2, 'privilege', '人事系统权限：员工信息管理、招聘管理', 1),
        (3, 'baseinfo', '运营经理，负责日常运营管理', 0),
        (3, 'privilege', '运营管理权限：数据分析、报表生成、KPI管理', 1),
        (4, 'baseinfo', '访客账户，权限受限', 0),
        (4, 'privilege', '访客权限：仅可查看公开信息', 1)
    ]

    cursor.executemany('''
        INSERT OR REPLACE INTO system_info (uid, info_type, content, is_sensitive)
        VALUES (?, ?, ?, ?)
    ''', system_data)

    conn.commit()
    conn.close()

# 生成JWT token
def generate_jwt_token(username, uid, role):
    payload = {
        'username': username,
        'uid': uid,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# 验证JWT token (存在算法验证绕过漏洞)
def verify_jwt_token(token):
    try:
        # 漏洞点：获取token头部的算法信息，允许none算法绕过
        header = jwt.get_unverified_header(token)
        algorithm = header.get('alg', JWT_ALGORITHM)

        if algorithm == 'none':
            # none算法绕过：不验证签名直接解析payload
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        else:
            # 正常算法验证
            payload = jwt.decode(token, JWT_SECRET, algorithms=[algorithm])
            return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# 路由定义
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error='请输入用户名和密码')

        # 验证用户
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        hashed_password = hashlib.md5(password.encode()).hexdigest()
        cursor.execute(
            'SELECT uid, username, role FROM users WHERE username = ? AND password = ?',
            (username, hashed_password)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            uid, username, role = user
            token = generate_jwt_token(username, uid, role)

            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('auth_token', token, httponly=True)
            return response
        else:
            return render_template('login.html', error='用户名或密码错误')

    # GET 请求，获取注册成功消息
    success_message = request.args.get('success')
    return render_template('login.html', success=success_message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        department = request.form.get('department', '普通部门')

        if not username or not password or not confirm_password or not email:
            return render_template('register.html', error='请填写所有必填字段')

        if password != confirm_password:
            return render_template('register.html', error='密码和确认密码不匹配')

        if len(username) < 3 or len(password) < 6:
            return render_template('register.html', error='用户名至少3位，密码至少6位')

        # 检查用户名是否已存在
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        cursor.execute('SELECT uid FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            conn.close()
            return render_template('register.html', error='用户名已存在')

        # 插入新用户
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, password, role, department, email)
            VALUES (?, ?, 'user', ?, ?)
        ''', (username, hashed_password, department, email))

        conn.commit()
        conn.close()

        return redirect(url_for('login', success='注册成功，请登录'))

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('auth_token')
    if not token:
        return redirect(url_for('login'))

    payload = verify_jwt_token(token)
    if not payload:
        return redirect(url_for('login'))

    # 如果是admin角色，获取当前用户uid对应的敏感信息
    sensitive_info = None
    if payload.get('role') == 'admin':
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # 使用JWT中的uid获取对应用户的敏感信息
        cursor.execute('''
            SELECT info_type, content, is_sensitive
            FROM system_info WHERE uid = ? AND is_sensitive = 1
        ''', (payload.get('uid'),))
        sensitive_data = cursor.fetchall()
        conn.close()

        if sensitive_data:
            sensitive_info = [{'type': info[0], 'content': info[1]} for info in sensitive_data]

    response = make_response(render_template('dashboard.html', user=payload, sensitive_info=sensitive_info))

    # 重要：将当前验证通过的token重新设置为cookie，这样修改后的token就会被保存
    response.set_cookie('auth_token', token, httponly=True)

    return response

@app.route('/api/user/<int:uid>')
def get_user_info(uid):
    token = request.cookies.get('auth_token')
    if not token:
        return render_template('profile.html', error='未授权访问，请先登录'), 401

    payload = verify_jwt_token(token)
    if not payload:
        return render_template('profile.html', error='认证失败，请重新登录'), 401

    # 漏洞点：没有验证当前用户是否有权限访问指定UID的信息
    # 但这里会被攻击者通过修改JWT中的UID来绕过

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 获取用户基础信息
    cursor.execute('''
        SELECT uid, username, role, department
        FROM users WHERE uid = ?
    ''', (uid,))
    user_info = cursor.fetchone()

    if not user_info:
        conn.close()
        return render_template('profile.html', error='用户不存在'), 404

    # 构建用户信息字典
    user_data = {
        'uid': user_info[0],
        'username': user_info[1],
        'role': user_info[2],
        'department': user_info[3],
        'status': 'active'
    }

    admin_privileges = None
    # 只有管理员角色才能看到敏感信息
    if payload.get('role') == 'admin':
        cursor.execute('''
            SELECT info_type, content, is_sensitive
            FROM system_info WHERE uid = ?
        ''', (uid,))
        system_info = cursor.fetchall()

        admin_privileges = []
        for info in system_info:
            if info[2]:  # is_sensitive
                admin_privileges.append({
                    'type': info[0],
                    'content': info[1]
                })

    conn.close()

    # 返回HTML页面
    response = make_response(render_template('profile.html',
                                            user_info=user_data,
                                            admin_privileges=admin_privileges))
    # 重要：将当前验证通过的token重新设置为cookie
    response.set_cookie('auth_token', token, httponly=True)

    return response

@app.route('/api/current-user')
def get_current_user():
    token = request.cookies.get('auth_token')
    if not token:
        return jsonify({'error': '未授权访问'}), 401

    payload = verify_jwt_token(token)
    if not payload:
        return jsonify({'error': '认证失败'}), 401

    response = jsonify({
        'uid': payload.get('uid'),
        'username': payload.get('username'),
        'role': payload.get('role')
    })

    # 重要：将当前验证通过的token重新设置为cookie
    response.set_cookie('auth_token', token, httponly=True)

    return response

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('index')))
    response.set_cookie('auth_token', '', expires=0)
    return response

@app.route('/employees')
def employees():
    token = request.cookies.get('auth_token')
    if not token:
        return redirect(url_for('login'))

    payload = verify_jwt_token(token)
    if not payload:
        return redirect(url_for('login'))

    # 检查是否为admin角色
    if payload.get('role') != 'admin':
        return render_template('error.html', error='权限不足，只有管理员可以查看员工列表'), 403

    # 获取所有员工信息
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT uid, username, role, department, email
        FROM users
        ORDER BY uid
    ''')
    employees_data = cursor.fetchall()
    conn.close()

    # 构建员工列表
    employees_list = []
    for emp in employees_data:
        employees_list.append({
            'uid': emp[0],
            'username': emp[1],
            'role': emp[2],
            'department': emp[3],
            'email': emp[4]
        })

    response = make_response(render_template('employees.html',
                                            user=payload,
                                            employees=employees_list))
    response.set_cookie('auth_token', token, httponly=True)
    return response

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=80, debug=False)