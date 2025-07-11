import os
from flask import Flask, redirect, request, session, url_for, render_template_string, jsonify
from flask_cors import CORS  # 导入CORS扩展
from google.oauth2.credentials import Credentials
import httplib2
from google.auth.transport.requests import AuthorizedSession
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient import errors

# --- 适配器保持不变，它已经完美工作 ---
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
# 添加CORS支持，允许来自开发和生产环境的请求
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000", "http://112.124.55.141:3000", "https://naviall.ai"], 
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "Authorization", "Accept"],
        "methods": ["GET", "POST", "OPTIONS"],
        "expose_headers": ["Content-Type", "Authorization"]
    }
})

app.secret_key = 'a_very_strong_and_random_secret_key' # 在生产环境中，这应该更复杂
CLIENT_SECRETS_FILE = 'client_secrets.json' 
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
# 警告：这里的回调URI需要在Google Cloud Console中更新
REDIRECT_URI_PROD = 'https://naviall.ai/callback'

def credentials_to_dict(credentials):
    return {'token': credentials.token, 'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri, 'client_id': credentials.client_id,
            'client_secret': credentials.client_secret, 'scopes': credentials.scopes}

# --- HTML模板保持不变 ---
DRIVE_BROWSER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Google Drive Content Selector</title>
    <style>
        body { font-family: sans-serif; display: flex; height: 100vh; margin: 0; }
        .sidebar { width: 30%; border-right: 2px solid #ccc; padding: 10px; overflow-y: auto; background-color: #f8f9fa; }
        .main-content { flex-grow: 1; padding: 20px; overflow-y: auto; }
        ul { list-style-type: none; padding: 0; }
        li { padding: 8px; border-bottom: 1px solid #ddd; }
        a { text-decoration: none; color: #007bff; cursor: pointer; }
        a:hover { text-decoration: underline; }
        .folder a { font-weight: bold; }
        .nav { margin-bottom: 20px; }
        #context-area .file-context { border: 1px solid #eee; background-color: #fdfdfd; padding: 15px; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        #context-area h3 { margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 10px; }
        #context-area pre { white-space: pre-wrap; word-wrap: break-word; background-color: #f3f3f3; padding: 10px; border-radius: 4px; }
        #loading { display: none; font-weight: bold; color: #dc3545; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h4>Browsing: {{ current_folder.name }}</h4>
        <div class="nav">
            {% if parent_id %}
                <a href="{{ url_for('drive_files', folder_id=parent_id) }}">⬆️ 返回上一级</a>
            {% endif %}
        </div>
        <ul>
            {% for item in items %}
                <li>
                    {% if item.is_folder %}
                        <span class="folder">
                            <a href="{{ url_for('drive_files', folder_id=item.id) }}">📁 {{ item.name }}</a>
                        </span>
                    {% else %}
                        <span class="file">
                            <a onclick="addFileToContext('{{ item.id }}', '{{ item.name }}')">📄 {{ item.name }}</a>
                        </span>
                    {% endif %}
                </li>
            {% else %}
                <li>这个文件夹是空的。</li>
            {% endfor %}
        </ul>
        <hr>
        <a href="{{ url_for('logout') }}">登出</a>
    </div>
    <div class="main-content">
        <h2>对话上下文</h2>
        <p>点击左侧的文件，其内容将显示在这里。</p>
        <div id="loading">正在加载文件内容...</div>
        <div id="context-area">
        </div>
    </div>

    <script>
        async function addFileToContext(fileId, fileName) {
            const loadingDiv = document.getElementById('loading');
            const contextArea = document.getElementById('context-area');
            loadingDiv.style.display = 'block';

            try {
                const response = await fetch(`/api/get_file_content/${fileId}`);
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || `服务器错误: ${response.statusText}`);
                }
                const data = await response.json();
                const fileDiv = document.createElement('div');
                fileDiv.className = 'file-context';
                const title = document.createElement('h3');
                title.textContent = data.filename;
                const content = document.createElement('pre');
                content.textContent = data.content;
                fileDiv.appendChild(title);
                fileDiv.appendChild(content);
                contextArea.appendChild(fileDiv);
            } catch (error) {
                alert(`加载文件失败: ${error.message}`);
            } finally {
                loadingDiv.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""

# --- 修改授权流程以使用生产环境的回调URI ---
# 注意：login 和 callback 函数中的 redirect_uri 都被修改了
@app.route('/')
def index():
    if 'credentials' in session:
        return redirect(url_for('drive_files'))
    return '<h1>欢迎</h1><a href="/login">使用 Google 登录</a>'

@app.route('/login')
def login():
    # 使用生产环境的URI
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI_PROD)
    authorization_url, state = flow.authorization_url(
        access_type='offline', prompt='consent')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session.get('state')
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI_PROD)
    
    # *** 修改这里：直接使用 request.url ***
    flow.fetch_token(authorization_response=request.url)
    
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    
    # 检查是否有redirect_uri参数，如果有则重定向到该URI
    redirect_uri = request.args.get('redirect_uri')
    if redirect_uri:
        # 返回一个HTML页面，该页面会自动关闭并通知父窗口授权成功
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>授权成功</title>
            <script>
            window.onload = function() {
                // 通知父窗口授权成功
                if (window.opener) {
                    window.opener.postMessage({type: 'GOOGLE_DRIVE_AUTH_SUCCESS'}, '*');
                    setTimeout(function() { window.close(); }, 1000);
                }
            };
            </script>
        </head>
        <body>
            <h2>Google Drive授权成功！</h2>
            <p>此窗口将自动关闭...</p>
        </body>
        </html>
        """)
    
    # 如果没有redirect_uri参数，则使用默认重定向
    return redirect(url_for('drive_files'))

@app.route('/drive-browser/', defaults={'folder_id': 'root'})
@app.route('/drive-browser/<path:folder_id>')
def drive_files(folder_id):
    if 'credentials' not in session: return redirect(url_for('login'))
    creds = Credentials(**session['credentials'])
    try:
        # *** 已移除代理设置 ***
        authed_session = AuthorizedSession(creds)
        http_adapter = Httplib2CompatibleAdapter(authorized_session=authed_session)
        drive_service = build('drive', 'v3', http=http_adapter)
        
        query = f"'{folder_id}' in parents and trashed = false"
        results = drive_service.files().list(
            q=query, pageSize=200, fields="nextPageToken, files(id, name, mimeType)").execute()
        
        file_items = [{'name': item['name'], 'id': item['id'],
                       'is_folder': item['mimeType'] == 'application/vnd.google-apps.folder'}
                      for item in results.get('files', [])]

        parent_id = None
        current_folder = {'name': 'My Drive', 'id': 'root'} 
        if folder_id != 'root':
            folder_metadata = drive_service.files().get(fileId=folder_id, fields='id, name, parents').execute()
            current_folder = folder_metadata
            if 'parents' in folder_metadata:
                parent_id = folder_metadata['parents'][0]
        session['credentials'] = credentials_to_dict(http_adapter.credentials)
        
        # 检查请求头中是否有Accept: application/json
        if request.headers.get('Accept') == 'application/json':
            # 返回JSON格式的文件列表
            files_json = [{
                "id": item['id'],
                "name": item['name'],
                "isFolder": item['is_folder'],
                "mimeType": "folder" if item['is_folder'] else "file"
            } for item in file_items]
            
            return jsonify({
                "success": True,
                "files": files_json,
                "currentFolder": {
                    "id": current_folder['id'],
                    "name": current_folder.get('name', 'My Drive')
                },
                "parentId": parent_id
            })
        
        # 否则返回HTML页面
        return render_template_string(
            DRIVE_BROWSER_TEMPLATE, items=file_items,
            current_folder=current_folder, parent_id=parent_id)
    except Exception as e:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"success": False, "error": str(e)}), 500
        return f"发生错误: {e}<br><a href='/logout'>尝试重新登录</a>"

@app.route('/api/get_file_content/<path:file_id>')
def get_file_content(file_id):
    if 'credentials' not in session: return jsonify({'error': 'Unauthorized'}), 401
    creds = Credentials(**session['credentials'])
    try:
        # *** 已移除代理设置 ***
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
            try: content = content_bytes.decode('utf-8')
            except UnicodeDecodeError: content = "[这是一个二进制文件，无法显示内容]"
        return jsonify({'filename': file_name, 'content': content})
    except errors.HttpError as error: return jsonify({'error': f'API请求失败: {error}'}), 500
    except Exception as e: return jsonify({'error': f'未知错误: {str(e)}'}), 500

@app.route('/logout')
def logout():
    session.pop('credentials', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # 在生产环境中，应该使用更安全的方式运行
    app.run(host='0.0.0.0', port=5000)
