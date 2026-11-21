"""Nara encrypted-message relay. No keys, file contents, or credentials are stored here.

It forwards opaque ciphertext between exactly one owner and one guest. TLS terminates
at the reverse proxy. End-to-end authentication/encryption must be done by clients.
"""
import asyncio, json, os, re, time, ipaddress, secrets
from aiohttp import web, WSMsgType, WSMessage

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

async def socket(request, ws=None):
    if ws is None:
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

# HTTPS long-poll transport for clients whose WebSocket upgrade is unavailable.
# Tokens authenticate a transport session; relay payloads remain end-to-end encrypted.
# No secrets are included in URLs, and server access logging must remain disabled.
POLL_LIMIT = 500
POLL_TTL = 75
poll_sessions = {}
CORS = {'Access-Control-Allow-Origin':'*','Cache-Control':'no-store',
        'Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'POST, OPTIONS'}
class PollSocket:
    def __init__(self):
        self.incoming=asyncio.Queue(maxsize=64);self.outgoing=asyncio.Queue(maxsize=64)
        self.closed=False;self.touched=time.monotonic();self.polling=False
    async def receive(self):
        return await self.incoming.get()
    async def send_json(self, data):
        if self.closed: raise ConnectionError('closed')
        if self.outgoing.full(): await self.close();raise ConnectionError('queue full')
        self.outgoing.put_nowait(data)
    async def close(self,code=1000,message=b''):
        if self.closed:return
        self.closed=True
        if not self.incoming.full():self.incoming.put_nowait(WSMessage(WSMsgType.CLOSED,None,None))
        if not self.outgoing.full():self.outgoing.put_nowait({'type':'_closed'})

def poll_response(data,status=200): return web.json_response(data,status=status,headers=CORS)
async def poll_options(request): return web.Response(status=204,headers=CORS)
async def poll_open(request):
    if len(poll_sessions)>=POLL_LIMIT:return poll_response({'error':'busy'},503)
    token=secrets.token_urlsafe(32); ws=PollSocket();poll_sessions[token]=ws
    async def runner():
        try:await socket(request,ws)
        finally:
            await ws.close()
            # Preserve closed state briefly so waiting clients can receive a close event.
    ws.task=asyncio.create_task(runner())
    return poll_response({'token':token})
async def poll_auth(request):
    try: body=await request.json()
    except Exception:return None,None
    if not isinstance(body,dict):return None,None
    token=body.get('token');ws=poll_sessions.get(token) if isinstance(token,str) and len(token)==43 else None
    if ws is not None:ws.touched=time.monotonic()
    return ws,body
async def poll_send(request):
    ws,body=await poll_auth(request)
    if not ws or ws.closed:return poll_response({'error':'closed'},410)
    data=body.get('data')
    if not isinstance(data,str) or len(data)>MAX_WIRE:return poll_response({'error':'invalid'},400)
    try:ws.incoming.put_nowait(WSMessage(WSMsgType.TEXT,data,''))
    except asyncio.QueueFull:return poll_response({'error':'busy'},429)
    return poll_response({'ok':True})
async def poll_read(request):
    ws,body=await poll_auth(request)
    if not ws:return poll_response({'error':'closed'},410)
    if ws.polling:return poll_response({'error':'already polling'},409)
    ws.polling=True
    try:
        if ws.closed and ws.outgoing.empty():return poll_response({'messages':[{'type':'_closed'}]})
        try:item=await asyncio.wait_for(ws.outgoing.get(),25)
        except asyncio.TimeoutError:return poll_response({'messages':[]})
        items=[item]
        while not ws.outgoing.empty() and len(items)<32:items.append(ws.outgoing.get_nowait())
        return poll_response({'messages':items})
    finally:ws.polling=False;ws.touched=time.monotonic()
async def poll_close(request):
    ws,body=await poll_auth(request)
    if ws:await ws.close()
    return poll_response({'ok':True})
async def poll_reaper(app):
    while True:
        await asyncio.sleep(15);now=time.monotonic()
        for token,ws in list(poll_sessions.items()):
            if now-ws.touched>POLL_TTL:
                poll_sessions.pop(token,None);await ws.close()
async def poll_start(app):app['poll_reaper']=asyncio.create_task(poll_reaper(app))
async def poll_cleanup(app):
    task=app['poll_reaper'];task.cancel()
    try:await task
    except asyncio.CancelledError:pass
    for ws in list(poll_sessions.values()):await ws.close()
    poll_sessions.clear()

app=web.Application(client_max_size=MAX_WIRE)
app.router.add_get('/health',health)
app.router.add_get('/ip',my_ip)
app.router.add_get('/relay',socket)
app.router.add_post('/poll/open',poll_open)
app.router.add_post('/poll/send',poll_send)
app.router.add_post('/poll/read',poll_read)
app.router.add_post('/poll/close',poll_close)
app.router.add_options('/poll/{tail}',poll_options)
app.on_startup.append(poll_start)
app.on_cleanup.append(poll_cleanup)
if __name__ == '__main__':
    # Never log URLs or messages: room identifiers and ciphertext need not be retained.
    web.run_app(app, host='0.0.0.0', port=int(os.environ.get('PORT','8080')), access_log=None, print=None)
