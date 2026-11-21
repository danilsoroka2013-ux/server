"""Nara encrypted-message relay. No keys, file contents, or credentials are stored here.

It forwards opaque ciphertext between exactly one owner and one guest. TLS terminates
at the reverse proxy. End-to-end authentication/encryption must be done by clients.
"""
import asyncio, json, os, re, time, ipaddress
from aiohttp import web, WSMsgType

ROOM = re.compile(r'^[A-Za-z0-9_-]{43}$')  # 256-bit unguessable room identifier
PAYLOAD = re.compile(r'^[A-Za-z0-9_-]+$')
MAX_WIRE = 1_600_000  # max includes base64 overhead
MAX_ROOMS = 500
IDLE_SECONDS = 900
rooms = {}

async def health(request):
    return web.json_response({'ok': True, 'protocol': 1}, headers={'Cache-Control':'no-store'})

async def peer_notice(ws, state, ip=None):
    if ws and not ws.closed:
        try: await ws.send_json({'type': state, **({'ip': ip} if ip else {})})
        except (ConnectionError, RuntimeError): pass

def client_ip(request):
    # Render edge currently supplies CF-Connecting-IP; never trust arbitrary X-Forwarded-For.
    # This value is informational, not proof of identity. Proxy behavior can change.
    candidate = request.headers.get('CF-Connecting-IP') if os.environ.get('RENDER') else request.remote
    try: return str(ipaddress.ip_address(candidate))
    except (ValueError, TypeError): return None

async def socket(request):
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=MAX_WIRE, compress=False)
    await ws.prepare(request)
    room_id = None; role = None; room = None; ip = client_ip(request)
    try:
        try: first = await asyncio.wait_for(ws.receive(), 10)
        except asyncio.TimeoutError: return ws
        if first.type != WSMsgType.TEXT or len(first.data) > 200: return ws
        try: join = json.loads(first.data)
        except (ValueError, TypeError): return ws
        if not isinstance(join, dict) or set(join) != {'type','room','role'} or join['type'] != 'join' or join['role'] not in ('owner','guest') or not isinstance(join['room'],str) or not ROOM.fullmatch(join['room']): return ws
        room_id, role = join['room'], join['role']
        room = rooms.get(room_id)
        if room is None:
            if role != 'owner' or len(rooms) >= MAX_ROOMS:
                await ws.send_json({'type':'unavailable'});return ws
            room = {};rooms[room_id] = room
        if role in room:
            await ws.send_json({'type':'unavailable'});return ws
        room[role] = ws
        ws._nara_ip = ip
        peerrole = 'guest' if role == 'owner' else 'owner'
        await ws.send_json({'type':'joined','ip':ip,'heartbeat':True})
        if peerrole in room:
            await peer_notice(ws,'peer_up',getattr(room[peerrole],'_nara_ip',None) if role=='owner' else None);await peer_notice(room[peerrole],'peer_up',ip if peerrole=='owner' else None)
        tokens=40.0; last=time.monotonic()
        while True:
            try: msg=await asyncio.wait_for(ws.receive(), IDLE_SECONDS)
            except asyncio.TimeoutError: break
            if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR): break
            if msg.type != WSMsgType.TEXT: break
            now=time.monotonic();tokens=min(40.0,tokens+(now-last)*4);last=now
            if tokens<1: await ws.close(code=1008,message=b'rate limit');break
            tokens-=1
            try: data=json.loads(msg.data)
            except (ValueError, TypeError): break
            if data == {'type':'ping'}:
                await ws.send_json({'type':'pong'});continue
            if not isinstance(data,dict) or set(data)!={'type','data'} or data.get('type')!='relay' or not isinstance(data.get('data'),str) or len(data['data'])<40 or len(data['data'])>MAX_WIRE-100 or not PAYLOAD.fullmatch(data['data']): break
            peer=room.get(peerrole)
            if peer is None or peer.closed:
                await peer_notice(ws,'peer_down');continue
            await peer.send_json(data)
    finally:
        if room is not None and role is not None and room.get(role) is ws:
            del room[role]
            other = room.get('guest' if role=='owner' else 'owner')
            await peer_notice(other,'peer_down')
            # When the owner leaves, revoke the room immediately.
            if role=='owner':
                rooms.pop(room_id,None)
                if other and not other.closed: await other.close(code=1001,message=b'owner left')
            elif not room:
                rooms.pop(room_id,None)
        if not ws.closed: await ws.close()
    return ws

async def my_ip(request):
    return web.json_response({'ip':client_ip(request)},headers={'Access-Control-Allow-Origin':'*','Cache-Control':'no-store'})

app=web.Application(client_max_size=MAX_WIRE)
app.router.add_get('/health',health)
app.router.add_get('/ip',my_ip)
app.router.add_get('/relay',socket)


# Offline gateway, embedded so this file replaces the old server.py by itself.
"""Experimental single-owner, single-instance offline model gateway.
The Drive object must already exist and be privately shared with the service account.
Never run multiple Render instances: request budget uses a process-local lock.
"""
import asyncio, base64, hashlib, hmac, json, os, re, time
from urllib.parse import urlsplit
from aiohttp import web, ClientSession, ClientTimeout

TOKEN = re.compile(r'^[A-Za-z0-9_-]{43}$')
FILE_ID = re.compile(r'^[A-Za-z0-9_-]{10,256}$')
AAD = b'nara-offline-v1'

async def read_limited(response,limit):
    data=bytearray()
    async for chunk in response.content.iter_chunked(16384):
        data.extend(chunk)
        if len(data)>limit: raise RuntimeError('response too large')
    return bytes(data)


def digest(s): return hashlib.sha256(s.encode('ascii')).hexdigest()
def secret(s): return isinstance(s,str) and TOKEN.fullmatch(s) is not None

def seal(key, obj):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce=os.urandom(12)
    data=json.dumps(obj,ensure_ascii=False,separators=(',',':')).encode()
    return json.dumps({'version':1,'nonce':base64.urlsafe_b64encode(nonce).decode(),'ciphertext':base64.urlsafe_b64encode(AESGCM(key).encrypt(nonce,data,AAD)).decode()},separators=(',',':')).encode()

def unseal(key, payload):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    o=json.loads(payload)
    if set(o)!={'version','nonce','ciphertext'} or o['version']!=1: raise ValueError('invalid envelope')
    n=base64.b64decode(o['nonce'],altchars=b'-_',validate=True); c=base64.b64decode(o['ciphertext'],altchars=b'-_',validate=True)
    if len(n)!=12 or len(c)>200000: raise ValueError('invalid envelope')
    return json.loads(AESGCM(key).decrypt(n,c,AAD))

class DriveStore:
    def __init__(self,file_id,credentials):
        if not FILE_ID.fullmatch(file_id): raise ValueError('invalid Google file id')
        from google.oauth2 import service_account
        self.file_id=file_id; self.credentials=service_account.Credentials.from_service_account_info(credentials,scopes=['https://www.googleapis.com/auth/drive'])
    async def auth(self):
        from google.auth.transport.requests import Request
        if not self.credentials.valid: await asyncio.to_thread(self.credentials.refresh,Request())
        return {'Authorization':'Bearer '+self.credentials.token}
    async def load(self):
        async with ClientSession(timeout=ClientTimeout(total=30)) as session:
            async with session.get('https://www.googleapis.com/drive/v3/files/'+self.file_id,params={'alt':'media','supportsAllDrives':'true'},headers=await self.auth(),allow_redirects=False) as r:
                if r.status!=200: raise RuntimeError('Drive read failed')
                data=await read_limited(r,200000)
                return data
    async def save(self,data):
        async with ClientSession(timeout=ClientTimeout(total=30)) as session:
            async with session.patch('https://www.googleapis.com/upload/drive/v3/files/'+self.file_id,params={'uploadType':'media','supportsAllDrives':'true'},headers={**await self.auth(),'Content-Type':'text/plain; charset=utf-8'},data=data,allow_redirects=False) as r:
                if r.status!=200: raise RuntimeError('Drive write failed')
                await r.read()

class Gateway:
    def __init__(self,store,key,bootstrap,allowed_hosts,provider=None):
        if len(key)!=32 or not secret(bootstrap): raise ValueError('master key or bootstrap secret invalid')
        self.store,self.key,self.bootstrap,self.allowed=store,key,bootstrap,set(allowed_hosts)
        self.lock=asyncio.Lock();self.slots=asyncio.Semaphore(2);self.recent=[];self.provider=provider or self.call_provider
    async def read(self):
        try:
            raw=await self.store.load()
            return None if not raw.strip() else unseal(self.key,raw)
        except Exception as exc:
            raise RuntimeError('secure storage unavailable') from exc
    async def write(self,v): await self.store.save(seal(self.key,v))
    def url(self,s):
        if not isinstance(s,str) or len(s)>300: raise ValueError('invalid URL')
        u=urlsplit(s)
        if u.scheme!='https' or not u.hostname or u.hostname.lower() not in self.allowed or u.username or u.password or u.port not in (None,443) or u.query or u.fragment or not u.path.endswith('/chat/completions'): raise ValueError('provider not permitted')
        return s
    def authorize(self,request,hashed):
        header=request.headers.get('Authorization','');token=header[7:] if header.startswith('Bearer ') else ''
        return secret(token) and isinstance(hashed,str) and hmac.compare_digest(digest(token),hashed)
    async def setup(self,request):
        try:
            payload=await request.json()
            if not isinstance(payload,dict): raise ValueError()
            admin=payload.get('admin'); guest=payload.get('guest'); model=payload.get('model'); name=payload.get('name'); key=payload.get('apiKey'); remaining=payload.get('remaining'); expires=payload.get('expires'); url=self.url(payload.get('url'))
            if not secret(admin) or not secret(guest) or hmac.compare_digest(admin,guest) or not isinstance(key,str) or not 1<=len(key)<=4096 or '\n' in key or '\r' in key or not isinstance(model,str) or not 1<=len(model)<=200 or not isinstance(name,str) or not 1<=len(name)<=100 or type(remaining)!=int or not 1<=remaining<=1000 or type(expires)!=int or not time.time()+60<expires<=time.time()+31*86400: raise ValueError()
            async with self.lock:
                old=await self.read();expected=digest(self.bootstrap) if old is None else old['adminHash']
                if not self.authorize(request,expected):return web.json_response({'error':'unauthorized'},status=401)
                if old is not None and not hmac.compare_digest(digest(admin),old['adminHash']):return web.json_response({'error':'admin rotation unsupported'},status=400)
                state={'adminHash':digest(admin),'guestHash':digest(guest),'apiKey':key,'url':url,'model':model,'name':name,'remaining':remaining,'expires':expires,'enabled':True}
                await self.write(state)
            return web.json_response({'ok':True,'name':name,'remaining':remaining,'expires':expires})
        except (ValueError,TypeError,KeyError,json.JSONDecodeError): return web.json_response({'error':'invalid configuration'},status=400)
        except Exception: return web.json_response({'error':'secure storage unavailable'},status=503)
    async def disable(self,request):
        try:
            async with self.lock:
                state=await self.read()
                if not state or not self.authorize(request,state.get('adminHash')):return web.json_response({'error':'unauthorized'},status=401)
                state.update(enabled=False,apiKey='',remaining=0,guestHash='');await self.write(state)
            return web.json_response({'ok':True})
        except Exception:return web.json_response({'error':'secure storage unavailable'},status=503)
    async def status(self,request):
        try:
            state=await self.read()
            if not state or not self.authorize(request,state.get('guestHash')):return web.json_response({'error':'unauthorized'},status=401)
            ok=state.get('enabled') is True and state.get('remaining',0)>0 and time.time()<state.get('expires',0)
            return web.json_response({'available':ok,'name':state.get('name','')},headers={'Cache-Control':'no-store'})
        except Exception:return web.json_response({'error':'secure storage unavailable'},status=503)
    async def chat(self,request):
        try:
            payload=await request.json()
            if not isinstance(payload,dict) or not isinstance(payload.get('messages'),list) or not isinstance(payload.get('tools'),list) or len(payload['messages'])>200 or len(payload['tools'])>150 or len(json.dumps(payload))>850000:raise ValueError()
            async with self.lock:
                state=await self.read()
                if not state or not self.authorize(request,state.get('guestHash')):return web.json_response({'error':'unauthorized'},status=401)
                if not state.get('enabled') or time.time()>=state.get('expires',0) or state.get('remaining',0)<=0:return web.json_response({'error':'access expired or disabled'},status=403)
                now=time.monotonic();self.recent=[x for x in self.recent if now-x<60]
                if len(self.recent)>=10:return web.json_response({'error':'rate limited'},status=429)
                self.recent.append(now);state['remaining']-=1;await self.write(state)
            async with self.slots: result=await self.provider(state,payload)
            return web.json_response(result,headers={'Cache-Control':'no-store'})
        except (ValueError,TypeError,json.JSONDecodeError):return web.json_response({'error':'invalid request'},status=400)
        except Exception:return web.json_response({'error':'model or secure storage unavailable'},status=503)
    async def call_provider(self,state,payload):
        data={'model':state['model'],'messages':payload['messages'],'stream':False,'max_tokens':4096}
        if payload['tools']:data['tools']=payload['tools']
        async with ClientSession(timeout=ClientTimeout(total=180)) as session:
            async with session.post(self.url(state['url']),json=data,headers={'Authorization':'Bearer '+state['apiKey'],'Content-Type':'application/json'},allow_redirects=False) as r:
                if r.status!=200:raise RuntimeError('provider error')
                raw=await read_limited(r,900000)
                value=json.loads(raw); msg=value['choices'][0]['message'];content=msg.get('content') or '';calls=msg.get('tool_calls') or []
                if not isinstance(content,str) or not isinstance(calls,list) or len(calls)>100:raise ValueError()
                return {'content':content,'calls':calls,'usage':value.get('usage'),'reasoning':msg.get('reasoning_content') or ''}

def install(app,gateway):
    async def cors_handler(request):return web.Response(status=204)
    @web.middleware
    async def cors(request,handler):
        response=await handler(request)
        if request.path.startswith('/offline/'):response.headers.update({'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Allow-Methods':'GET, POST, OPTIONS','Cache-Control':'no-store'})
        return response
    app.middlewares.append(cors)
    app.router.add_post('/offline/setup',gateway.setup);app.router.add_post('/offline/disable',gateway.disable);app.router.add_get('/offline/status',gateway.status);app.router.add_post('/offline/chat',gateway.chat);app.router.add_route('OPTIONS','/offline/{tail:.*}',cors_handler)

def from_environment():
    key=base64.b64decode(os.environ['NARA_MASTER_KEY'],altchars=b'-_',validate=True)
    creds=json.loads(os.environ['NARA_DRIVE_SERVICE_ACCOUNT_JSON']); file_id=os.environ['NARA_DRIVE_FILE_ID'];token=os.environ['NARA_SETUP_TOKEN']
    hosts=[x.strip().lower() for x in os.environ.get('NARA_AI_HOST_ALLOWLIST','api.openai.com,openrouter.ai,router.bynara.id,api.xkiro.com,text.pollinations.ai').split(',') if x.strip()]
    if not hosts or any(not re.fullmatch(r'[a-z0-9.-]+',h) or h in ('localhost','metadata.google.internal') or re.fullmatch(r'[0-9.]+',h) for h in hosts):raise ValueError('bad allowlist')
    return Gateway(DriveStore(file_id,creds),key,token,hosts)


if os.environ.get('NARA_OFFLINE_ENABLED') == '1':
    install(app,from_environment())
if __name__ == '__main__':
    web.run_app(app, host='0.0.0.0', port=int(os.environ.get('PORT','8080')), access_log=None, print=None)
