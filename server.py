import asyncio
import json
import os
import random
import socket
import websockets

from session import Session

JITTER_MIN = 0.05
JITTER_MAX = 0.40


async def _jitter() -> None:
    await asyncio.sleep(random.uniform(JITTER_MIN, JITTER_MAX))


def _get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _try_start_ngrok(port: int, token: str = None):
    try:
        from pyngrok import ngrok, conf as ngrok_conf
        if token:
            ngrok_conf.get_default().auth_token = token
        tunnel = ngrok.connect(port, "http")
        url = tunnel.public_url
        return url.replace("https://", "wss://").replace("http://", "ws://")
    except Exception:
        return None


class ConnectedPeer:
    def __init__(self, nick: str, pubkey: str, websocket):
        self.nick = nick
        self.pubkey = pubkey
        self.ws = websocket


class MultiServer:
    def __init__(self, host_session: Session):
        self.host = host_session
        self._peers: dict = {} 
        self._groups: dict = {} 

    async def _send(self, peer: ConnectedPeer, msg: dict) -> None:
        try:
            await peer.ws.send(json.dumps(msg))
        except Exception:
            pass

    async def _broadcast(self, msg: dict, exclude: str = None) -> None:
        tasks = []
        for nick, peer in list(self._peers.items()):
            if nick != exclude:
                tasks.append(_broadcast_one(peer, msg))
        if tasks:
            await asyncio.gather(*tasks)

    async def _send_user_list(self, to_peer: ConnectedPeer) -> None:
        users = [
            {"nick": self.host.nick, "pubkey": self.host.identity.public_key_b64(), "is_host": True}
        ] + [
            {"nick": p.nick, "pubkey": p.pubkey, "is_host": False}
            for p in self._peers.values()
            if p.nick != to_peer.nick
        ]
        await self._send(to_peer, {"type": "user_list", "users": users})

    async def handle(self, websocket) -> None:
        peer = None
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=10)
            msg = json.loads(raw)

            if msg.get("type") != "join":
                await websocket.close(1002, "Expected join")
                return

            nick = msg["nick"]
            pubkey = msg["pubkey"]

            if nick == self.host.nick or nick in self._peers:
                await websocket.send(json.dumps({
                    "type": "error",
                    "reason": f"Nick '{nick}' is already taken"
                }))
                await websocket.close()
                return

            peer = ConnectedPeer(nick, pubkey, websocket)
            self._peers[nick] = peer

            await self._send_user_list(peer)
            await self._broadcast({
                "type": "user_joined",
                "nick": nick,
                "pubkey": pubkey,
            }, exclude=nick)

            self.host.add_peer(nick, pubkey)
            self.host.print_system(f"\033[32m{nick}\033[0m joined ({len(self._peers)} online)")

            async for raw in websocket:
                await self._route(peer, json.loads(raw))

        except asyncio.TimeoutError:
            pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            if peer and peer.nick in self._peers:
                await self._disconnect(peer)

    async def _disconnect(self, peer: ConnectedPeer) -> None:
        del self._peers[peer.nick]
        self.host.remove_peer(peer.nick)
        self.host.print_system(f"\033[33m{peer.nick}\033[0m disconnected")
        await self._broadcast({"type": "user_left", "nick": peer.nick})

    async def _route(self, sender: ConnectedPeer, msg: dict) -> None:
        t = msg.get("type")
        if t == "dm":
            await self._route_dm(sender, msg)
        elif t == "group_create":
            await self._route_group_create(sender, msg)
        elif t == "group_add":
            await self._route_group_add(sender, msg)
        elif t == "group_msg":
            await self._route_group_msg(sender, msg)

    async def _route_dm(self, sender: ConnectedPeer, msg: dict) -> None:
        payload = {
            "type": "dm",
            "from": sender.nick,
            "ciphertext": msg["ciphertext"],
            "nonce": msg["nonce"],
        }
        dm_session = self.host.get_dm_session(sender.nick)
        if dm_session:
            try:
                text = dm_session.decrypt(msg["ciphertext"], msg["nonce"])
                if text:
                    self.host.print_dm(sender.nick, text)
                    print("> ", end="", flush=True)
            except Exception:
                pass
        await self._broadcast(payload, exclude=sender.nick)

    async def _route_group_create(self, sender: ConnectedPeer, msg: dict) -> None:
        members = msg.get("members", [])
        encrypted_keys = msg.get("encrypted_keys", {})
        group_name = msg.get("name", "")

        self._groups[group_name] = members

        for nick in members:
            if nick == sender.nick:
                continue
            if nick == self.host.nick:
                if self.host.nick in encrypted_keys:
                    try:
                        group_key = self.host.identity.decrypt_group_key(encrypted_keys[self.host.nick])
                        self.host.add_group(group_name, group_key, members)
                        self.host.print_system(
                            f"Added to group \033[35m#{group_name}\033[0m by {sender.nick}"
                        )
                    except Exception as e:
                        self.host.print_error(f"Group key decrypt failed: {e}")
                continue

            target = self._peers.get(nick)
            if target and nick in encrypted_keys:
                await _broadcast_one(target, {
                    "type": "group_create",
                    "name": group_name,
                    "members": members,
                    "creator": sender.nick,
                    "encrypted_key": encrypted_keys[nick],
                })

        self.host.print_system(f"\033[35m#{group_name}\033[0m created by {sender.nick}")

    async def _route_group_add(self, sender: ConnectedPeer, msg: dict) -> None:
        group_name = msg.get("group")
        new_nick = msg.get("nick")
        encrypted_key = msg.get("encrypted_key")

        if not group_name or not new_nick or not encrypted_key:
            await self._send(sender, {"type": "error", "reason": "Invalid group_add message"})
            return

        members = self._groups.get(group_name)
        if members is None:
            await self._send(sender, {"type": "error", "reason": f"Group '#{group_name}' not found"})
            return

        if sender.nick not in members and sender.nick != self.host.nick:
            await self._send(sender, {"type": "error", "reason": "You are not a member of this group"})
            return

        if new_nick in members:
            await self._send(sender, {"type": "error", "reason": f"'{new_nick}' is already in #{group_name}"})
            return

        if new_nick == self.host.nick:
            new_pubkey = self.host.identity.public_key_b64()
        else:
            target_peer = self._peers.get(new_nick)
            if not target_peer:
                await self._send(sender, {"type": "error", "reason": f"User '{new_nick}' is not online"})
                return
            new_pubkey = target_peer.pubkey

        new_members = members + [new_nick]
        self._groups[group_name] = new_members

        if new_nick == self.host.nick:
            try:
                group_key = self.host.identity.decrypt_group_key(encrypted_key)
                self.host.add_group(group_name, group_key, new_members)
                self.host.print_system(
                    f"Added to group \033[35m#{group_name}\033[0m by {sender.nick}"
                )
            except Exception as e:
                self.host.print_error(f"Group key decrypt failed: {e}")
        else:
            target_peer = self._peers.get(new_nick)
            if target_peer:
                await _broadcast_one(target_peer, {
                    "type": "group_create",
                    "name": group_name,
                    "members": new_members,
                    "creator": sender.nick,
                    "encrypted_key": encrypted_key,
                })

        notify_payload = {
            "type": "group_member_added",
            "group": group_name,
            "nick": new_nick,
            "pubkey": new_pubkey,
            "adder": sender.nick,
        }

        for nick in members:
            if nick == sender.nick:
                await self._send(sender, notify_payload)
                continue
            if nick == self.host.nick:
                self.host.add_peer_to_group(group_name, new_nick, new_pubkey)
                self.host.print_system(
                    f"\033[33m{sender.nick}\033[0m added \033[32m{new_nick}\033[0m "
                    f"to group \033[35m#{group_name}\033[0m"
                )
                print("> ", end="", flush=True)
                continue
            target = self._peers.get(nick)
            if target:
                await _broadcast_one(target, notify_payload)

    async def _route_group_msg(self, sender: ConnectedPeer, msg: dict) -> None:
        group_name = msg.get("group")
        members = self._groups.get(group_name, [])

        payload = {
            "type": "group_msg",
            "group": group_name,
            "from": sender.nick,
            "ciphertext": msg["ciphertext"],
            "nonce": msg["nonce"],
        }

        for nick in members:
            if nick == sender.nick:
                continue
            if nick == self.host.nick:
                gs = self.host.get_group(group_name)
                if gs:
                    try:
                        text = gs.decrypt(msg["ciphertext"], msg["nonce"])
                        if text:
                            self.host.print_group(group_name, sender.nick, text)
                            print("> ", end="", flush=True)
                    except Exception:
                        self.host.print_error(f"Group msg decrypt failed in #{group_name}")
                continue
            target = self._peers.get(nick)
            if target:
                await _broadcast_one(target, payload)

    async def host_kick(self, nick: str) -> None:
        target = self._peers.get(nick)
        if target:
            await self._send(target, {"type": "kicked", "reason": "Kicked by host"})
            await target.ws.close()
            self.host.print_system(f"Kicked \033[31m{nick}\033[0m")
        else:
            self.host.print_error(f"User '{nick}' not found")


async def _broadcast_one(peer: ConnectedPeer, msg: dict) -> None:
    await _jitter()
    try:
        await peer.ws.send(json.dumps(msg))
    except Exception:
        pass


async def run_server(session: Session, port: int = 8765):
    server = MultiServer(session)

    token = os.environ.get("NGROK_AUTHTOKEN")
    public_url = _try_start_ngrok(port, token)

    local_ip = _get_local_ip()
    local_url = f"ws://{local_ip}:{port}"

    session.print_system("Your addresses (share with peers):")

    if public_url:
        print(f"\n  \033[32m[Internet] {public_url}\033[0m")
    else:
        print(f"\n  \033[33m[ngrok unavailable — internet access disabled]\033[0m")
        print(f"  \033[90mTo enable: set NGROK_AUTHTOKEN env variable\033[0m")
        print(f"  \033[90m           get free token at https://ngrok.com\033[0m")

    print(f"  \033[36m[LAN]      {local_url}\033[0m\n")

    async with websockets.serve(server.handle, "0.0.0.0", port):
        session.print_system(
            f"Listening on port {port} | Host: \033[36m{session.nick}\033[0m"
        )
        session.print_system("Type /help for commands\n")
        await _host_input_loop(session, server)


async def _host_input_loop(session: Session, server: MultiServer) -> None:
    loop = asyncio.get_event_loop()
    while True:
        try:
            print("> ", end="", flush=True)
            line = await loop.run_in_executor(None, input, "")
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                await _handle_host_command(line, session, server)
            else:
                session.print_system("Use /help to see commands")
        except (KeyboardInterrupt, EOFError):
            break


async def _handle_host_command(line: str, session: Session, server: MultiServer) -> None:
    parts = line.split()
    cmd = parts[0].lower()

    if cmd == "/help":
        print("""
  \033[36m/users\033[0m                          — список онлайн
  \033[36m/dm <nick> <text>\033[0m               — личное сообщение
  \033[36m/group new <name> <n1> <n2>\033[0m     — создать группу
  \033[36m/group add <name> <nick>\033[0m        — добавить в группу
  \033[36m/group <name> <text>\033[0m            — написать в группу
  \033[36m/kick <nick>\033[0m                    — кикнуть пользователя
  \033[36m/help\033[0m                           — эта справка
""")

    elif cmd == "/users":
        users = session.online_users()
        if users:
            session.print_system("Online: " + ", ".join(f"\033[33m{u}\033[0m" for u in users))
        else:
            session.print_system("No users connected")

    elif cmd == "/kick":
        if len(parts) < 2:
            session.print_error("Usage: /kick <nick>")
            return
        await server.host_kick(parts[1])

    elif cmd == "/dm":
        if len(parts) < 3:
            session.print_error("Usage: /dm <nick> <text>")
            return
        nick = parts[1]
        text = " ".join(parts[2:])
        dm = session.get_dm_session(nick)
        if not dm:
            session.print_error(f"User '{nick}' not found")
            return
        await _jitter()
        encrypted = dm.encrypt(text)
        await server._broadcast({
            "type": "dm",
            "from": session.nick,
            "ciphertext": encrypted["ciphertext"],
            "nonce": encrypted["nonce"],
        })
        session.print_dm(f"{session.nick} → {nick}", text)

    elif cmd == "/group":
        if len(parts) < 2:
            session.print_error("Usage: /group new <name> <nicks...> | /group add <name> <nick> | /group <name> <text>")
            return

        if parts[1] == "new":
            if len(parts) < 4:
                session.print_error("Usage: /group new <name> <nick1> [nick2 ...]")
                return
            name = parts[2]
            members = parts[3:]
            if session.nick not in members:
                members = [session.nick] + members
            missing = [m for m in members if m != session.nick and m not in session.peers]
            if missing:
                session.print_error(f"Users not online: {', '.join(missing)}")
                return
            gs = session.create_group(name, members)
            server._groups[name] = members
            encrypted_keys = {}
            for nick in members:
                if nick == session.nick:
                    continue
                peer_pub = session.peers.get(nick)
                if peer_pub:
                    encrypted_keys[nick] = gs.encrypt_key_for_peer(peer_pub)
            for nick, enc_key in encrypted_keys.items():
                target = server._peers.get(nick)
                if target:
                    await _broadcast_one(target, {
                        "type": "group_create",
                        "name": name,
                        "members": members,
                        "creator": session.nick,
                        "encrypted_key": enc_key,
                    })
            session.print_system(f"Group \033[35m#{name}\033[0m created with: {', '.join(members)}")

        elif parts[1] == "add":
            if len(parts) < 4:
                session.print_error("Usage: /group add <name> <nick>")
                return
            name = parts[2]
            new_nick = parts[3]
            gs = session.get_group(name)
            if not gs:
                session.print_error(f"Group '#{name}' not found")
                return
            current_members = server._groups.get(name, [])
            if new_nick in current_members:
                session.print_error(f"User '{new_nick}' is already in #{name}")
                return
            if new_nick == session.nick:
                session.print_error("You are already in the group")
                return
            peer_pub = session.peers.get(new_nick)
            if not peer_pub:
                session.print_error(f"User '{new_nick}' not found online")
                return
            encrypted_key = gs.encrypt_key_for_peer(peer_pub)
            new_members = current_members + [new_nick]
            server._groups[name] = new_members

            target_peer = server._peers.get(new_nick)
            if target_peer:
                await _broadcast_one(target_peer, {
                    "type": "group_create",
                    "name": name,
                    "members": new_members,
                    "creator": session.nick,
                    "encrypted_key": encrypted_key,
                })

            notify_payload = {
                "type": "group_member_added",
                "group": name,
                "nick": new_nick,
                "pubkey": peer_pub,
                "adder": session.nick,
            }
            session.add_peer_to_group(name, new_nick, peer_pub)
            for nick in current_members:
                if nick == session.nick:
                    continue
                target = server._peers.get(nick)
                if target:
                    await _broadcast_one(target, notify_payload)

            session.print_system(
                f"Added \033[32m{new_nick}\033[0m to group \033[35m#{name}\033[0m"
            )

        else:
            name = parts[1]
            text = " ".join(parts[2:])
            gs = session.get_group(name)
            if not gs:
                session.print_error(f"Group '#{name}' not found")
                return
            await _jitter()
            encrypted = gs.encrypt(text)
            members = server._groups.get(name, [])
            for nick in members:
                if nick == session.nick:
                    continue
                target = server._peers.get(nick)
                if target:
                    await _broadcast_one(target, {
                        "type": "group_msg",
                        "group": name,
                        "from": session.nick,
                        "ciphertext": encrypted["ciphertext"],
                        "nonce": encrypted["nonce"],
                    })
            session.print_group(name, session.nick, text)
    else:
        session.print_error(f"Unknown command: {cmd}. Type /help")
