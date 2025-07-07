import os
from flask import Flask, redirect, request, session, url_for
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# 我们需要这两个库来构建最终的适配器
from google.auth.transport.requests import AuthorizedSession
# 我们将直接构造这个库所期望的响应类型
import httplib2 


# --- 这是我们最终的、正确的适配器 ---
class Httplib2CompatibleAdapter:
    """
    这个适配器拥有 googleapiclient 期望的 http.request 接口，
    包括方法的签名和返回值。
    它在内部使用一个配置好的 AuthorizedSession 来发送真正的网络请求。
    """
    def __init__(self, authorized_session: AuthorizedSession):
        self.session = authorized_session

    # 1. 定义一个与 googleapiclient 调用方式完全匹配的 request 方法
    def request(self, uri, method='GET', body=None, headers=None, **kwargs):
        
        # 2. 使用内部的、我们测试成功的 session 来发送请求
        response = self.session.request(
            method=method,
            url=uri,
            data=body,
            headers=headers,
            timeout=20 
        )

        # 3. 这是最关键的一步：将 requests 的 Response 对象，
        #    “翻译”成 googleapiclient 期望的 (httplib2.Response, content) 元组
        
        # 3a. 创建一个 httplib2.Response 对象，并传入响应头
        httplib2_response = httplib2.Response(dict(response.headers))
        
        # 3b. 为这个对象添加 googleapiclient 必需的 .status 属性
        httplib2_response.status = response.status_code
        
        # 3c. 获取响应内容
        content_bytes = response.content

        # 4. 返回这个包含两项的、格式完全正确的元组
        return httplib2_response, content_bytes

    # 5. 为适配器添加 credentials 属性，以便外部可以获取刷新后的凭据
    @property
    def credentials(self):
        return self.session.credentials

# --- 适配器定义结束 ---


app = Flask(__name__)
app.secret_key = 'your_super_secret_key_for_session' 
CLIENT_SECRETS_FILE = 'client_secrets.json' 
# 为了调试，我们简化 SCOPES，只请求必需的权限
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']
REDIRECT_URI = 'http://127.0.0.1:5000/callback'
PROXY_PORT = 7890

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

@app.route('/')
def index():
    if 'credentials' in session:
        return '<h1>您已登录</h1><p><a href="/drive_files">查看文件</a></p><p><a href="/logout">登出</a></p>'
    return '<h1>欢迎</h1><a href="/login">使用 Google 登录</a>'

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    authorization_url, state = flow.authorization_url(
        access_type='offline', prompt='consent')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('drive_files'))

@app.route('/drive_files')
def drive_files():
    if 'credentials' not in session:
        return redirect(url_for('login'))
        
    creds = Credentials(**session['credentials'])
    
    try:
        authed_session = AuthorizedSession(creds)
        authed_session.proxies = {
           'http': f'http://127.0.0.1:{PROXY_PORT}',
           'https': f'http://127.0.0.1:{PROXY_PORT}',
        }
        
        http_adapter = Httplib2CompatibleAdapter(authorized_session=authed_session)

        drive_service = build('drive', 'v3', http=http_adapter)
        
        results = drive_service.files().list(
            pageSize=10, fields="nextPageToken, files(id, name)").execute()
        items = results.get('files', [])

        session['credentials'] = credentials_to_dict(http_adapter.credentials)

        if not items:
            return "在您的 Drive 中未找到任何文件。<br><a href='/'>返回主页</a>"

        file_list_html = "<h1>您的 Google Drive 文件:</h1><ul>"
        for item in items:
            file_list_html += f"<li>{item['name']} ({item['id']})</li>"
        file_list_html += "</ul><a href='/'>返回主页</a>"
        
        return file_list_html

    except Exception as e:
        return f"发生错误: {e}<br><a href='/logout'>尝试重新登录</a>"

@app.route('/logout')
def logout():
    session.pop('credentials', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(debug=True)