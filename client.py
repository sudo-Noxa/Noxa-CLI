import asyncio
import json
import random
import websockets

from session import Session

JITTER_MIN = 0.05
JITTER_MAX = 0.40

COVER_INTERVAL_MIN = 5.0
COVER_INTERVAL_MAX = 15.0


async def _jitter() -> None:
    await asyncio.sleep(random.uniform(JITTER_MIN, JITTER_MAX))


async def run_client(session: Session, url: str) -> None:
    session.print_system(f"Connecting to {url} ...")
    extra_headers = {"ngrok-skip-browser-warning": "1"}

    try:
        async with websockets.connect(url, additional_headers=extra_headers) as ws:
            await ws.send(json.dumps({
                "type": "join",
                "nick": session.nick,
                "pubkey": session.identity.public_key_b64(),
            }))

            raw = await asyncio.wait_for(ws.recv(), timeout=10)
            msg = json.loads(raw)

            if msg.get("type") == "error":
                session.print_error(msg.get("reason", "Server rejected connection"))
                return

            if msg.get("type") != "user_list":
                session.print_error("Unexpected server response")
                return

            host_nick = None
            for user in msg["users"]:
                session.add_peer(user["nick"], user["pubkey"])
                if user.get("is_host"):
                    host_nick = user["nick"]

            session.print_system(
                f"Joined as \033[36m{session.nick}\033[0m | "
                f"Host: \033[33m{host_nick}\033[0m | "
                f"Online: {len(msg['users'])} users"
            )
            session.print_system("Type /help for commands\n")

            await asyncio.gather(
                _receive_loop(ws, session),
                _send_loop(ws, session),
                _cover_traffic_loop(ws, session),
            )

    except websockets.exceptions.ConnectionClosed as e:
        session.print_system(f"Disconnected: {e}")
    except asyncio.TimeoutError:
        session.print_error("Server did not respond in time")
    except OSError as e:
        session.print_error(f"Connection failed: {e}")


async def _cover_traffic_loop(ws, session: Session) -> None:
    while True:
        await asyncio.sleep(random.uniform(COVER_INTERVAL_MIN, COVER_INTERVAL_MAX))
        try:
            peers = list(session.peers.keys())
            if not peers:
                continue
            nick = random.choice(peers)
            dm = session.get_dm_session(nick)
            if not dm:
                continue
            cover = dm.make_cover()
            await ws.send(json.dumps({
                "type": "dm",
                "ciphertext": cover["ciphertext"],
                "nonce": cover["nonce"],
            }))
        except Exception:
            pass


async def _receive_loop(ws, session: Session) -> None:
    async for raw in ws:
        try:
            msg = json.loads(raw)
            await _handle_incoming(msg, ws, session)
        except Exception as e:
            session.print_error(f"Receive error: {e}")


async def _handle_incoming(msg: dict, ws, session: Session) -> None:
    t = msg.get("type")

    if t == "user_joined":
        session.add_peer(msg["nick"], msg["pubkey"])
        session.print_system(f"\033[32m{msg['nick']}\033[0m joined")
        print("> ", end="", flush=True)

    elif t == "user_left":
        session.remove_peer(msg["nick"])
        session.print_system(f"\033[33m{msg['nick']}\033[0m left")
        print("> ", end="", flush=True)

    elif t == "dm":
        sender = msg["from"]
        dm = session.get_dm_session(sender)
        if dm:
            try:
                text = dm.decrypt(msg["ciphertext"], msg["nonce"])
                if text:
                    session.print_dm(sender, text)
                    print("> ", end="", flush=True)
            except Exception:
                pass

    elif t == "group_create":
        name = msg["name"]
        members = msg["members"]
        enc_key = msg["encrypted_key"]
        creator = msg.get("creator", "?")
        try:
            group_key = session.identity.decrypt_group_key(enc_key)
            session.add_group(name, group_key, members)
            session.print_system(
                f"Added to group \033[35m#{name}\033[0m "
                f"by \033[33m{creator}\033[0m ({len(members)} members)"
            )
            print("> ", end="", flush=True)
        except Exception as e:
            session.print_error(f"Failed to join group #{name}: {e}")

    elif t == "group_member_added":
        group = msg["group"]
        new_nick = msg["nick"]
        new_pubkey = msg["pubkey"]
        adder = msg.get("adder", "?")
        gs = session.get_group(group)
        if gs:
            session.add_peer_to_group(group, new_nick, new_pubkey)
            session.print_system(
                f"\033[33m{adder}\033[0m added \033[32m{new_nick}\033[0m "
                f"to group \033[35m#{group}\033[0m"
            )
            print("> ", end="", flush=True)

    elif t == "group_msg":
        group = msg["group"]
        sender = msg["from"]
        gs = session.get_group(group)
        if gs:
            try:
                text = gs.decrypt(msg["ciphertext"], msg["nonce"])
                if text:
                    session.print_group(group, sender, text)
                    print("> ", end="", flush=True)
            except Exception:
                pass

    elif t == "kicked":
        reason = msg.get("reason", "no reason")
        session.print_system(f"\033[31mYou were kicked: {reason}\033[0m")
        raise websockets.exceptions.ConnectionClosed(None, None)

    elif t == "error":
        session.print_error(msg.get("reason", "Unknown error"))


async def _send_loop(ws, session: Session) -> None:
    loop = asyncio.get_event_loop()
    while True:
        try:
            print("> ", end="", flush=True)
            line = await loop.run_in_executor(None, input, "")
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                await _handle_command(line, ws, session)
            else:
                session.print_system("Use /help to see commands")
        except (KeyboardInterrupt, EOFError):
            break


async def _handle_command(line: str, ws, session: Session) -> None:
    parts = line.split()
    cmd = parts[0].lower()

    if cmd == "/help":
        print("""
  \033[36m/users\033[0m                          — список онлайн/online list
  \033[36m/dm <nick> <text>\033[0m               — личное сообщение/personal message
  \033[36m/group new <name> <n1> <n2>\033[0m     — создать группу/create group
  \033[36m/group add <name> <nick>\033[0m        — добавить в группу/invite in group
  \033[36m/group <name> <text>\033[0m            — написать в группу/write in group
  \033[36m/help\033[0m                           — эта справка/help list
""")

    elif cmd == "/users":
        users = session.online_users()
        if users:
            session.print_system("Online: " + ", ".join(f"\033[33m{u}\033[0m" for u in users))
        else:
            session.print_system("No other users online")

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
        await ws.send(json.dumps({
            "type": "dm",
            "ciphertext": encrypted["ciphertext"],
            "nonce": encrypted["nonce"],
        }))
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
            encrypted_keys = {}
            for nick in members:
                if nick == session.nick:
                    continue
                peer_pub = session.peers.get(nick)
                if peer_pub:
                    encrypted_keys[nick] = gs.encrypt_key_for_peer(peer_pub)
            await _jitter()
            await ws.send(json.dumps({
                "type": "group_create",
                "name": name,
                "members": members,
                "encrypted_keys": encrypted_keys,
            }))
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
            current_members = session.group_members.get(name, [])
            if new_nick in current_members:
                session.print_error(f"User '{new_nick}' is already in #{name}")
                return
            peer_pub = session.peers.get(new_nick)
            if not peer_pub:
                session.print_error(f"User '{new_nick}' not found online")
                return
            encrypted_key = gs.encrypt_key_for_peer(peer_pub)
            await _jitter()
            await ws.send(json.dumps({
                "type": "group_add",
                "group": name,
                "nick": new_nick,
                "encrypted_key": encrypted_key,
            }))
            session.print_system(
                f"Adding \033[32m{new_nick}\033[0m to group \033[35m#{name}\033[0m..."
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
            await ws.send(json.dumps({
                "type": "group_msg",
                "group": name,
                "ciphertext": encrypted["ciphertext"],
                "nonce": encrypted["nonce"],
            }))
            session.print_group(name, session.nick, text)
    else:
        session.print_error(f"Unknown command: {cmd}. Type /help")
