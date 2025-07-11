# 处理Google登录并将凭证返回给阿里云；作为代理，接收阿里云的请求并安全地调用Google API
import os
from flask import Flask, redirect, request, session, url_for, jsonify
from flask_cors import CORS
from google.oauth2.credentials import Credentials
import httplib2
from google.auth.transport.requests import AuthorizedSession
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient import errors

# --- 适配器 (无需修改) ---
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

# --- Flask 应用设置 ---
app = Flask(__name__)
# 允许来自你的阿里云应用的跨域请求
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://112.124.55.141:3000", "http://localhost:3000"], # 你的阿里云前端地址
        "supports_credentials": True,
        "methods": ["GET", "OPTIONS"],
        "allow_headers": ["Authorization"],
    }
})
app.secret_key = 'aws_proxy_random_secret_key_for_state'
CLIENT_SECRETS_FILE = 'client_secrets.json' 
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

# --- Google Cloud Console 中配置的回调地址 ---
# 这个地址必须指向本服务器 (AWS 代理)
REDIRECT_URI_PROD = 'https://naviall.ai/callback'

# --- 你的阿里云前端接收凭证的地址 ---
# 这是认证成功后，用户浏览器被重定向的目标地址
ALIYUN_FRONTEND_CALLBACK_URL = 'http://112.124.55.141:8000/gdrive/callback-receiver'


# --- 认证流程 ---

@app.route('/login')
def login():
    """
    步骤1：认证的起点。
    当阿里云应用的用户需要登录Google时，会跳转到这个地址。
    """
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI_PROD)
    authorization_url, state = flow.authorization_url(
        access_type='offline', prompt='consent')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    """
    步骤2：接收Google的回调，并将凭证安全地返回给阿里云前端。
    这是整个架构的核心。
    """
    state = session.pop('state', None)
    # 在生产环境中，应该验证 state 是否匹配来防止CSRF攻击

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI_PROD)
    
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        # 如果用户拒绝或发生错误，重定向回阿里云并附带错误信息
        return redirect(f"{ALIYUN_FRONTEND_CALLBACK_URL}#error=auth_failed")

    credentials = flow.credentials
    
    # 构建包含凭证的URL hash，然后重定向回阿里云前端
    # hash 对服务器是不可见的，保证了凭证在传输过程中的安全
    refresh_token_part = f"&refresh_token={credentials.refresh_token}" if credentials.refresh_token else ""
    redirect_url = (
        f"{ALIYUN_FRONTEND_CALLBACK_URL}"
        f"#access_token={credentials.token}"
        f"{refresh_token_part}"
    )
    return redirect(redirect_url)

# --- 无状态代理 API ---

def build_drive_service_from_token(access_token: str):
    """辅助函数：根据传入的 access_token 创建一个临时的 Google Drive 服务实例"""
    credentials = Credentials(token=access_token)
    authed_session = AuthorizedSession(credentials)
    http_adapter = Httplib2CompatibleAdapter(authorized_session=authed_session)
    return build('drive', 'v3', http=http_adapter)

@app.route('/api/proxy/drive/files/<path:folder_id>')
def proxy_drive_files(folder_id):
    """代理API：获取文件列表。不使用session，只依赖请求头中的token。"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未提供有效的Authorization认证头'}), 401
    
    access_token = auth_header.split(' ')[1]

    try:
        drive_service = build_drive_service_from_token(access_token)
        query = f"'{folder_id}' in parents and trashed = false"
        results = drive_service.files().list(
            q=query, pageSize=300, fields="files(id, name, mimeType)").execute()
        
        file_items = [{
            'id': item['id'],
            'name': item['name'],
            'is_folder': item.get('mimeType') == 'application/vnd.google-apps.folder'
        } for item in results.get('files', [])]

        return jsonify({'items': file_items})
    except errors.HttpError as error:
        if error.resp.status in [401, 403]:
            return jsonify({'error': 'Google授权失败或Token已过期'}), 401
        return jsonify({'error': f'Google API错误: {error}'}), 500
    except Exception as e:
        return jsonify({'error': f'代理服务器内部错误: {str(e)}'}), 500

@app.route('/api/proxy/drive/content/<path:file_id>')
def proxy_get_file_content(file_id):
    """代理API：获取文件内容。同样只依赖token。"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未提供有效的Authorization认证头'}), 401
    access_token = auth_header.split(' ')[1]

    try:
        drive_service = build_drive_service_from_token(access_token)
        meta = drive_service.files().get(fileId=file_id, fields='name, mimeType').execute()
        
        if 'google-apps' in meta.get('mimeType', ''):
            content_bytes = drive_service.files().export_media(fileId=file_id, mimeType='text/plain').execute()
        else:
            content_bytes = drive_service.files().get_media(fileId=file_id).execute()
        
        try:
            content = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            content = "[二进制文件，无法显示内容]"
            
        return jsonify({'filename': meta.get('name'), 'content': content})
    except errors.HttpError as error:
        if error.resp.status in [401, 403]:
            return jsonify({'error': 'Google授权失败或Token已过期'}), 401
        return jsonify({'error': f'Google API错误: {error}'}), 500
    except Exception as e:
        return jsonify({'error': f'代理服务器内部错误: {str(e)}'}), 500

if __name__ == '__main__':
    # 对于生产环境，请使用 Gunicorn 或 uWSGI 运行
    app.run(host='0.0.0.0', port=5000)