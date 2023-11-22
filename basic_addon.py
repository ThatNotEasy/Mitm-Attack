# Author: Pari Malam

import OpenSSL
import requests
from OpenSSL import SSL
from OpenSSL.SSL import Context, WantReadError
from urllib3.connection import SSLConnection

def handle_client(connection):
    response = "HTTP/1.1 200 OK\r\n\r\n".encode('utf-8')
    connection.send(response)

# Client to Server Request Forwarder
def forward_request(connection, client_request):
    server_address = (connection.target_host, connection.target_port)
    server_connection = SSLConnection(connection.ssl_context, server_address)
    server_connection.connect()
    server_connection.send(client_request)
    server_response = server_connection.recv()
    connection.send(server_response)

def ssl_handle_client(connection):
    connection.ssl_ctx = Context(SSL.SSLv23_METHOD)
    connection.ssl_ctx.use_privatekey(OpenSSL.crypto.PKey())
    connection.ssl_ctx.use_certificate(OpenSSL.crypto.X509())

    try:
        connection.ssl_accept()
    except WantReadError:
        pass

    handle_client(connection)

def ssl_forward_request(connection, client_request):
    ssl_handle_client(connection)
    forward_request(connection, client_request)

server = SSLConnection(Context(SSL.SSLv23_METHOD), ('localhost', 12345), server_side=True)
server.bind(('localhost', 12345))
server.listen(5)

while True:
    client_connection = server.accept()
    ssl_handle_client(client_connection)
    client_request = client_connection.recv()
    ssl_forward_request(client_connection, client_request)
