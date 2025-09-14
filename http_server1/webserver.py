import http.server
import socketserver

class CSC458Handler(http.server.SimpleHTTPRequestHandler):

    # Disable logging DNS lookups
    def address_string(self):
        return str(self.client_address[0])


PORT = 80

Handler = CSC458Handler
httpd = socketserver.TCPServer(("", PORT), Handler)
print("Server1: httpd serving at port", PORT)
httpd.serve_forever()
