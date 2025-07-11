import os
from flask import Flask, redirect, request, session, url_for, jsonify
from flask_cors import CORS
from google.oauth2.credentials import Credentials
import httplib2
from google.auth.transport.requests import AuthorizedSession
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient import errors

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
# CORS 设置至关重要，确保你的 ChatApp 源在允许列表中
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000", "http://112.124.55.141:3000"], 
        "supports_credentials": True,
        "allow_headers": ["Content-Type"],
        "methods": ["GET", "POST", "OPTIONS"]
    }
})

app.secret_key = 'a_very_strong_and_random_secret_key'
CLIENT_SECRETS_FILE = 'client_secrets.json' 
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
# 这个回调 URI 必须与 Google Cloud Console 中配置的完全一致
REDIRECT_URI_PROD = 'https://naviall.ai/callback'

def credentials_to_dict(credentials):
    return {'token': credentials.token, 'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri, 'client_id': credentials.client_id,
            'client_secret': credentials.client_secret, 'scopes': credentials.scopes}

# --- 授权流程 API ---

# 新增: 步骤1 - 前端调用此API获取Google授权URL
@app.route('/api/auth/google/url')
def get_google_auth_url():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI_PROD)
    authorization_url, state = flow.authorization_url(
        access_type='offline', prompt='consent')
    session['state'] = state
    return jsonify({'auth_url': authorization_url})

# 修改: 步骤2 - Google回调此地址，此地址返回JS代码，通过postMessage将凭证发给父窗口
@app.route('/callback')
def callback():
    state = session.get('state')
    # 验证 state (此处省略，但生产环境建议添加)
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI_PROD)
    
    flow.fetch_token(authorization_response=request.url)
    
    credentials = flow.credentials
    creds_dict = credentials_to_dict(credentials)

    # 返回一个HTML页面，用JS将凭证发送给打开此窗口的父页面
    # !! 重要: 'http://112.124.55.141:3000' 必须是你的ChatApp的确切源
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head><title>认证成功</title></head>
    <body>
        <script>
            window.opener.postMessage({{
                'type': 'google-auth-success',
                'credentials': {creds_dict}
            }}, 'http://112.124.55.141:3000');
            window.close();
        </script>
        <p>认证成功，此窗口将自动关闭。</p>
    </body>
    </html>
    """
    return html_response

# --- 数据 API ---

# 新增: API端点，用于获取文件和文件夹列表
# 它通过POST请求体接收凭证，而不是从session中读取
@app.route('/api/drive/files/', defaults={'folder_id': 'root'}, methods=['POST'])
@app.route('/api/drive/files/<path:folder_id>', methods=['POST'])
def api_drive_files(folder_id):
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
        
        return jsonify({'files': file_items})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 修改: get_file_content 转为纯API, 通过POST接收凭证
@app.route('/api/get_file_content/<path:file_id>', methods=['POST'])
def api_get_file_content(file_id):
    creds_data = request.json.get('credentials')
    if not creds_data:
        return jsonify({'error': 'Unauthorized'}), 401

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
        
        return jsonify({'filename': file_name, 'content': content})
    except errors.HttpError as error:
        return jsonify({'error': f'API请求失败: {error}'}), 500
    except Exception as e:
        return jsonify({'error': f'未知错误: {str(e)}'}), 500


if __name__ == '__main__':
    # 注意：确保在生产环境中使用Gunicorn或类似的WSGI服务器
    app.run(host='0.0.0.0', port=5000, debug=True)