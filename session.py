import base64
import hashlib
import random
import datetime
from crypto import IdentityKey, DMSession, GroupSession

ADJECTIVES = [
    "silent", "dark", "swift", "iron", "ghost",
    "cold", "wild", "blind", "lone", "hollow",
    "crimson", "neon", "frozen", "void", "lost"
]
NOUNS = [
    "wolf", "raven", "fox", "hawk", "cipher",
    "shade", "echo", "storm", "byte", "proxy",
    "node", "ghost", "signal", "mask", "drift"
]


def generate_nick() -> str:
    return f"{random.choice(ADJECTIVES)}_{random.choice(NOUNS)}#{random.randint(1000,9999)}"


def key_fingerprint(pubkey_b64: str) -> str:
    raw = base64.b64decode(pubkey_b64)
    h = hashlib.sha256(raw).hexdigest()[:20].upper()
    return " ".join(h[i:i+4] for i in range(0, 20, 4))


class Session:
    def __init__(self):
        self.nick: str = generate_nick()
        self.identity = IdentityKey()
        self.peers: dict = {}
        self._dm_sessions: dict = {}
        self.groups: dict = {}
        self.group_members: dict = {}

    def add_peer(self, nick: str, pubkey_b64: str) -> None:
        self.peers[nick] = pubkey_b64

    def remove_peer(self, nick: str) -> None:
        self.peers.pop(nick, None)
        self._dm_sessions.pop(nick, None)

    def online_users(self) -> list:
        return list(self.peers.keys())

    def get_dm_session(self, nick: str):
        if nick not in self.peers:
            return None
        if nick not in self._dm_sessions:
            peer_pub = self.peers[nick]
            shared = self.identity.compute_shared_key(peer_pub, role="dm")
            self._dm_sessions[nick] = DMSession(shared)
        return self._dm_sessions[nick]

    def get_fingerprint(self, nick: str) -> str | None:
        pubkey = self.peers.get(nick)
        if not pubkey:
            return None
        return key_fingerprint(pubkey)

    def my_fingerprint(self) -> str:
        return key_fingerprint(self.identity.public_key_b64())

    def create_group(self, name: str, members: list) -> GroupSession:
        gs = GroupSession()
        self.groups[name] = gs
        self.group_members[name] = list(members)
        return gs

    def add_group(self, name: str, group_key: bytes, members: list) -> None:
        self.groups[name] = GroupSession(group_key)
        self.group_members[name] = list(members)

    def get_group(self, name: str):
        return self.groups.get(name)

    def add_peer_to_group(self, group_name: str, nick: str, pubkey_b64: str) -> None:
        if group_name in self.group_members:
            if nick not in self.group_members[group_name]:
                self.group_members[group_name].append(nick)
        if pubkey_b64:
            self.add_peer(nick, pubkey_b64)

    def print_dm(self, sender: str, text: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        if sender.startswith(self.nick):
            print(f"\r\033[90m[{ts}]\033[0m \033[90m[DM]\033[0m \033[36mYou\033[0m: {text}")
        else:
            print(f"\r\033[90m[{ts}]\033[0m \033[90m[DM]\033[0m \033[33m{sender}\033[0m: {text}")

    def print_group(self, group: str, sender: str, text: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        color = "\033[36m" if sender == self.nick else "\033[33m"
        print(f"\r\033[90m[{ts}]\033[0m \033[35m[#{group}]\033[0m {color}{sender}\033[0m: {text}")

    def print_system(self, text: str) -> None:
        print(f"\r\033[90m[sys] {text}\033[0m")

    def print_error(self, text: str) -> None:
        print(f"\r\033[91m[err] {text}\033[0m")

    def print_fingerprint(self, nick: str, fp: str, is_self: bool = False) -> None:
        label = "\033[36mYou\033[0m" if is_self else f"\033[33m{nick}\033[0m"
        print(f"\r\033[90m[fp]\033[0m {label}  \033[33m{fp}\033[0m")
