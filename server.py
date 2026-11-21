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
if __name__ == '__main__':
    # Never log URLs or messages: room identifiers and ciphertext need not be retained.
    web.run_app(app, host='0.0.0.0', port=int(os.environ.get('PORT','8080')), access_log=None, print=None)
