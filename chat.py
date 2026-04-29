import colorama
colorama.init()
import argparse
import asyncio

from session import Session
from client import run_client

BANNER = """
\033[36m
  ███╗   ██╗ ██████╗ ██╗  ██╗ █████╗ 
  ████╗  ██║██╔═══██╗╚██╗██╔╝██╔══██╗
  ██╔██╗ ██║██║   ██║ ╚███╔╝ ███████║
  ██║╚██╗██║██║   ██║ ██╔██╗ ██╔══██║
  ██║ ╚████║╚██████╔╝██╔╝ ██╗██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  
\033[0m
  \033[90mE2E encrypted · no accounts · multi-user · groups\033[0m
"""


def parse_args():
    parser = argparse.ArgumentParser(description="Noxa CLI v1")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--host", action="store_true", help="Стать хостом")
    mode.add_argument("--connect", metavar="URL", help="Подключиться к хосту")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--nick", type=str)
    return parser.parse_args()


async def main():
    print(BANNER)
    args = parse_args()

    session = Session()
    if args.nick:
        session.nick = args.nick

    print(f"  Your nickname : \033[36m{session.nick}\033[0m")

    try:
        if args.host:
            from server import run_server
            await run_server(session, port=args.port)
        else:
            await run_client(session, url=args.connect)
    except KeyboardInterrupt:
        print("\n\n\033[90m[sys] Session ended. Goodbye.\033[0m\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
