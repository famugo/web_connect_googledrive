import sys
import os
import json
import socket
import platform
from flask import Flask, request, redirect, jsonify, session
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import AuthorizedSession
import httplib2

# 在本地开发环境中允许OAuth使用HTTP
# 注意：这只应在开发环境中设置，生产环境应使用HTTPS
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# --- 适配器保持不变 ---
class Httplib2CompatibleAdapter:
    def __init__(self, authorized_session: AuthorizedSession):
        self.session = authorized_session
    def request(self, uri, method='GET', body=None, headers=None, **kwargs):
        response = self.session.request(
            method=method, url=uri, data=body, headers=headers, timeout=30)
        httplib2_response = httplib2.Response(dict(response.headers))
        httplib2_response.status = response.status_code
        content_bytes = response.content
        return httplib2_response, content_bytes
    @property
    def credentials(self):
        return self.session.credentials
# --- 适配器定义结束 ---


app = Flask(__name__)
# 禁用URL尾部斜杠重定向，避免OPTIONS请求被重定向
app.url_map.strict_slashes = False

# CORS 设置至关重要，确保你的 ChatApp 源在允许列表中
# 允许的前端源列表
ALLOWED_ORIGINS = [
    "http://localhost:3000",       # 本地开发环境
    "http://112.124.55.141:3000",  # 云端测试环境
    "https://naviall.ai",          # 旧生产环境
    "http://naviall.com",          # 新生产环境 - HTTP
    "https://naviall.com"          # 新生产环境 - HTTPS
]

# 添加全局OPTIONS请求处理
@app.after_request
def after_request(response):
    # 获取请求的Origin
    origin = request.headers.get('Origin', '')
    
    # 如果请求来自允许的源，添加CORS头部
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept, Origin'
        response.headers['Access-Control-Max-Age'] = '3600'
    
    # 对于OPTIONS请求，总是返回200 OK
    if request.method == 'OPTIONS':
        response.status_code = 200
    
    return response

CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS, 
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "Authorization", "Accept"],
        "methods": ["GET", "POST", "OPTIONS"],
        "expose_headers": ["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
        "max_age": 3600
    },
    r"/callback": {
        "origins": ALLOWED_ORIGINS,
        "supports_credentials": True,
        "allow_headers": ["Content-Type"],
        "methods": ["GET", "POST", "OPTIONS"]
    },
    # 明确为 /api/auth/google/url 添加 CORS 配置
    r"/api/auth/google/url": {
        "origins": ALLOWED_ORIGINS,
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "Authorization", "Accept"],
        "methods": ["GET", "OPTIONS"],
        "max_age": 3600
    }
})

app.secret_key = 'a_very_strong_and_random_secret_key'
CLIENT_SECRETS_FILE = 'client_secrets.json' 
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

# 注意: 回调URI必须与Google Cloud Console中配置的完全一致
# Google OAuth不允许使用IP地址作为回调URL，必须使用有效的域名

# 根据环境变量或命令行参数自动选择回调URI
import os
import sys

# 默认使用本地开发环境
DEFAULT_REDIRECT_URI = 'http://localhost:3000/callback'

# 定义可用的回调URI选项
REDIRECT_URI_OPTIONS = {
    'local_frontend': 'http://localhost:5000/callback',     # 本地后端端口（不是前端端口）
    'local_backend': 'http://localhost:5000/callback',      # 本地后端端口
    'cloud_test': 'http://112.124.55.141:5000/callback',    # 云端测试环境（使用后端端口）
    'production': 'https://naviall.ai/callback',            # 旧生产环境
    'production_new': 'https://naviall.ai/callback'         # 新生产环境（使用AWS服务器作为回调）
}

# 从环境变量或命令行参数获取环境设置
def get_environment():
    # 检查命令行参数
    if len(sys.argv) > 1 and sys.argv[1] in REDIRECT_URI_OPTIONS:
        return sys.argv[1]
    
    # 检查环境变量
    env = os.environ.get('GOOGLE_OAUTH_ENV')
    if env and env in REDIRECT_URI_OPTIONS:
        return env
    
    # 检查是否在AWS环境
    if os.environ.get('AWS_EXECUTION_ENV') or os.path.exists('/etc/ec2-environment'):
        return 'production_new'  # 默认使用新的生产环境
    
    # 检查是否在Linux服务器上
    import socket
    hostname = socket.gethostname()
    if hostname.startswith('ip-') or hostname.startswith('ec2-'):
        return 'production_new'  # 默认使用新的生产环境
    
    # 检查是否在Ubuntu系统上
    try:
        with open('/etc/os-release', 'r') as f:
            if 'Ubuntu' in f.read():
                # 检查是否有特定环境标记文件
                if os.path.exists('/etc/naviall_env_old'):
                    return 'production'  # 使用旧的生产环境
                else:
                    return 'production_new'  # 默认使用新的生产环境
    except:
        pass
    
    # 默认使用本地开发环境
    return 'local_frontend'

# 设置当前环境的重定向URI
CURRENT_ENV = get_environment()
REDIRECT_URI = REDIRECT_URI_OPTIONS[CURRENT_ENV]
print(f"[信息] 当前环境: {CURRENT_ENV}, 使用回调URI: {REDIRECT_URI}")

# 注意：不能使用IP地址作为回调URL
# 如果需要在测试服务器上运行，请为服务器配置域名

def credentials_to_dict(credentials):
    return {'token': credentials.token, 'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri, 'client_id': credentials.client_id,
            'client_secret': credentials.client_secret, 'scopes': credentials.scopes}

# --- 授权流程 API ---

# 新增: 步骤1 - 前端调用此API获取Google授权URL
@app.route('/api/auth/google/url', methods=['GET', 'OPTIONS'])
def get_google_auth_url():
    # 处理 OPTIONS 请求
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
        response.headers['Access-Control-Max-Age'] = '3600'
        return response
        
    # 处理 GET 请求
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    authorization_url, state = flow.authorization_url(
        access_type='offline', prompt='consent')
    session['state'] = state
    
    response = jsonify({'auth_url': authorization_url})
    
    # 手动添加 CORS 头，确保跨域请求能正确工作
    # 记录请求信息以便调试
    print(f"[DEBUG] 收到授权URL请求，来源: {request.headers.get('Origin', '未知')}, 返回URL: {authorization_url}")
    print(f"[DEBUG] 当前环境: {CURRENT_ENV}, 使用回调URI: {REDIRECT_URI}")
    print(f"[DEBUG] 请求头: {dict(request.headers)}")
    
    # 确保设置正确的CORS头部
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

# 修改: 步骤2 - Google回调此地址，此地址返回JS代码，通过postMessage将凭证发给父窗口
@app.route('/callback')
def callback():
    state = session.get('state')
    # 验证 state (此处省略，但生产环境建议添加)
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    
    flow.fetch_token(authorization_response=request.url)
    
    credentials = flow.credentials
    creds_dict = credentials_to_dict(credentials)

    # 返回一个HTML页面，用JS将凭证发送给打开此窗口的父页面
    # 使用更安全的方式处理多个可能的来源
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>认证成功</title>
        <style>
            body {{ font-family: Arial, sans-serif; text-align: center; padding: 20px; }}
            .status {{ margin: 20px 0; padding: 10px; border-radius: 5px; }}
            .success {{ background-color: #d4edda; color: #155724; }}
            .error {{ background-color: #f8d7da; color: #721c24; }}
            pre {{ text-align: left; background: #f8f9fa; padding: 10px; border-radius: 5px; overflow: auto; }}
        </style>
    </head>
    <body>
        <h2>Google Drive 授权成功</h2>
        <div id="status" class="status success">正在处理凭证...</div>
        <div id="debug"></div>
        
        <script>
            // 调试函数
            function log(message, data) {{
                console.log(message, data);
                const debugDiv = document.getElementById('debug');
                const logEntry = document.createElement('div');
                logEntry.innerHTML = `<strong>${{message}}</strong>: ${{JSON.stringify(data, null, 2)}}`;
                debugDiv.appendChild(logEntry);
            }}
            
            function setStatus(message, isError = false) {{
                const statusDiv = document.getElementById('status');
                statusDiv.textContent = message;
                statusDiv.className = `status ${{isError ? 'error' : 'success'}}`;
            }}
            
            // 定义允许的来源列表
            const allowedOrigins = [
                'https://naviall.ai',
                'http://112.124.55.141:3000',
                'http://localhost:3000',
                '*' /* 在调试阶段允许所有来源，生产环境应移除 */
            ];
            
            // 凭证对象
            const credentials = {creds_dict};
            log('获取到凭证', {{
                hasToken: !!credentials.token,
                hasRefreshToken: !!credentials.refresh_token,
                scopes: credentials.scopes
            }});
            
            // 保存凭证到localStorage（当前窗口）
            try {{
                localStorage.setItem('googleUserCredentials', JSON.stringify(credentials));
                log('凭证已保存到当前窗口的localStorage', '成功');
            }} catch (e) {{
                log('保存凭证到当前窗口localStorage失败', e.toString());
            }}
            
            // 尝试多种方法发送凭证
            let messageSent = false;
            
            // 方法1: 检查window.opener并使用postMessage
            if (window.opener) {{
                // 尝试使用通配符发送消息
                try {{
                    log('尝试使用通配符发送消息', '*');
                    window.opener.postMessage({{
                        'type': 'google-auth-success',
                        'credentials': credentials,
                        'timestamp': new Date().toISOString()
                    }}, '*');
                    messageSent = true;
                    setStatus('凭证已发送！正在关闭窗口...');
                }} catch (e) {{
                    log('使用通配符发送消息失败', e.toString());
                }}
                
                // 尝试使用特定来源发送消息
                if (!messageSent) {{
                    for (const origin of allowedOrigins) {{
                        if (origin === '*') continue; // 已尝试过
                        
                        try {{
                            log('尝试发送凭证到来源', origin);
                            window.opener.postMessage({{
                                'type': 'google-auth-success',
                                'credentials': credentials,
                                'timestamp': new Date().toISOString()
                            }}, origin);
                            messageSent = true;
                        }} catch (err) {{
                            log(`向 ${{origin}} 发送消息失败`, err.toString());
                        }}
                    }}
                }}
                
                // 尝试直接在父窗口中设置localStorage
                if (!messageSent) {{
                    try {{
                        log('尝试将凭证存储在父窗口的localStorage', '开始');
                        window.opener.localStorage.setItem('googleUserCredentials', JSON.stringify(credentials));
                        log('凭证已存储在父窗口的localStorage', '成功');
                        messageSent = true;
                        setStatus('凭证已直接存储到父窗口！正在关闭...');
                    }} catch (e) {{
                        log('尝试存储凭证到父窗口localStorage失败', e.toString());
                    }}
                }}
            }} else {{
                log('错误', '找不到父窗口');
            }}
            
            // 方法2: 使用重定向作为备选方案
            if (!messageSent) {{
                // 如果所有方法都失败，尝试重定向回前端应用
                setStatus('尝试重定向回应用...');
                
                // 确定重定向URL
                let redirectUrl;
                const currentUrl = window.location.href;
                
                if (currentUrl.includes('localhost')) {{
                    // 本地开发环境
                    redirectUrl = 'http://localhost:3000/chat?googleAuth=success';
                }} else if (currentUrl.includes('112.124.55.141')) {{
                    // 云端测试环境
                    redirectUrl = 'http://112.124.55.141:3000/chat?googleAuth=success';
                }} else if (currentUrl.includes('naviall.com')) {{
                    redirectUrl = 'https://naviall.com/chat?googleAuth=success';
                }} else {{
                    redirectUrl = 'https://naviall.ai/chat?googleAuth=success';
                }}
                
                log('即将重定向到', redirectUrl);
                
                // 添加凭证作为URL参数（仅用于调试，实际应用中应避免在URL中传递敏感信息）
                // redirectUrl += '&credentials=' + encodeURIComponent(JSON.stringify(credentials));
                
                // 3秒后重定向
                setTimeout(() => {{
                    window.location.href = redirectUrl;
                }}, 3000);
            }} else {{
                // 如果消息已发送，尝试关闭窗口
                setTimeout(() => {{
                    try {{
                        window.close();
                    }} catch (e) {{
                        log('关闭窗口失败', e.toString());
                    }}
                }}, 3000);
            }}
        </script>
        
        <p>认证成功，此窗口将在凭证发送后自动关闭。</p>
        <p>如果窗口没有自动关闭，请手动关闭并返回应用。</p>
    </body>
    </html>
    """
    return html_response

# --- 数据 API ---

# 增加OPTIONS方法处理，确保预检请求能正确响应
@app.route('/api/drive/files/', defaults={'folder_id': 'root'}, methods=['OPTIONS'])
@app.route('/api/drive/files/<path:folder_id>', methods=['OPTIONS'])
def api_drive_files_options(folder_id):
    response = jsonify({
        'status': 'success',
        'message': 'CORS preflight request successful'
    })
    # 手动设置CORS头部
    response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
    response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept')
    response.headers.add('Access-Control-Max-Age', '3600')
    return response

# 新增: API端点，用于获取文件和文件夹列表
# 它通过POST请求体接收凭证，而不是从ession中读取
@app.route('/api/drive/files/', defaults={'folder_id': 'root'}, methods=['POST'])
@app.route('/api/drive/files/<path:folder_id>', methods=['POST'])
def api_drive_files(folder_id):
    # 记录请求信息以便调试
    print(f"[DEBUG] 收到文件列表请求，来源: {request.headers.get('Origin', '未知')}, 文件夹ID: {folder_id}")
    print(f"[DEBUG] 请求头: {dict(request.headers)}")
    
    creds_data = request.json.get('credentials')
    if not creds_data:
        return jsonify({'error': 'Credentials not provided'}), 401
    
    try:
        creds = Credentials(**creds_data)
        authed_session = AuthorizedSession(creds)
        http_adapter = Httplib2CompatibleAdapter(authorized_session=authed_session)
        drive_service = build('drive', 'v3', http=http_adapter)
        
        query = f"'{folder_id}' in parents and trashed = false"
        results = drive_service.files().list(
            q=query, pageSize=200, fields="files(id, name, mimeType)").execute()
        
        file_items = [{'name': item['name'], 'id': item['id'],
                       'is_folder': item['mimeType'] == 'application/vnd.google-apps.folder'}
                      for item in results.get('files', [])]
        
        response = jsonify({'files': file_items})
        
        # 手动添加 CORS 头部，确保跨域请求能正确工作
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        return response
    except Exception as e:
        print(f"[ERROR] 获取文件列表失败: {str(e)}")
        error_response = jsonify({'error': str(e)})
        
        # 即使发生错误也要添加 CORS 头部
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            error_response.headers['Access-Control-Allow-Origin'] = origin
            error_response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        return error_response, 500

# 增加OPTIONS方法处理，确保预检请求能正确响应
@app.route('/api/get_file_content/<path:file_id>', methods=['OPTIONS'])
def api_get_file_content_options(file_id):
    response = jsonify({
        'status': 'success',
        'message': 'CORS preflight request successful'
    })
    # 手动设置CORS头部
    origin = request.headers.get('Origin', '')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept, Origin'
        response.headers['Access-Control-Max-Age'] = '3600'
    return response

# 修改: get_file_content 转为纯API, 通过POST接收凭证
@app.route('/api/get_file_content/<path:file_id>', methods=['POST'])
def api_get_file_content(file_id):
    # 记录请求信息以便调试
    print(f"[DEBUG] 收到文件内容请求，来源: {request.headers.get('Origin', '未知')}, 文件ID: {file_id}")
    print(f"[DEBUG] 请求头: {dict(request.headers)}")
    
    creds_data = request.json.get('credentials')
    if not creds_data:
        error_response = jsonify({'error': 'Unauthorized'})
        # 即使发生错误也要添加 CORS 头部
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            error_response.headers['Access-Control-Allow-Origin'] = origin
            error_response.headers['Access-Control-Allow-Credentials'] = 'true'
        return error_response, 401

    try:
        creds = Credentials(**creds_data)
        authed_session = AuthorizedSession(creds)
        http_adapter = Httplib2CompatibleAdapter(authorized_session=authed_session)
        drive_service = build('drive', 'v3', http=http_adapter)
        
        file_metadata = drive_service.files().get(fileId=file_id, fields='name, mimeType').execute()
        file_name = file_metadata.get('name')
        mime_type = file_metadata.get('mimeType')
        content = ""

        if 'google-apps' in mime_type:
            content_bytes = drive_service.files().export_media(fileId=file_id, mimeType='text/plain').execute()
            content = content_bytes.decode('utf-8')
        else:
            content_bytes = drive_service.files().get_media(fileId=file_id).execute()
            try:
                content = content_bytes.decode('utf-8')
            except UnicodeDecodeError:
                content = "[这是一个二进制文件，无法显示内容]"
        
        response = jsonify({'filename': file_name, 'content': content})
        
        # 手动添加 CORS 头部，确保跨域请求能正确工作
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        return response
    except errors.HttpError as error:
        print(f"[ERROR] 获取文件内容失败 (API错误): {error}")
        error_response = jsonify({'error': f'API请求失败: {error}'})
        # 即使发生错误也要添加 CORS 头部
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            error_response.headers['Access-Control-Allow-Origin'] = origin
            error_response.headers['Access-Control-Allow-Credentials'] = 'true'
        return error_response, 500
    except Exception as e:
        print(f"[ERROR] 获取文件内容失败 (未知错误): {str(e)}")
        error_response = jsonify({'error': f'未知错误: {str(e)}'})
        # 即使发生错误也要添加 CORS 头部
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            error_response.headers['Access-Control-Allow-Origin'] = origin
            error_response.headers['Access-Control-Allow-Credentials'] = 'true'
        return error_response, 500


if __name__ == '__main__':
    # 注意：确保在生产环境中使用Gunicorn或类似的WSGI服务器
    app.run(host='0.0.0.0', port=5000, debug=True)