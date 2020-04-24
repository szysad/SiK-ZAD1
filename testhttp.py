import subprocess
import sys
import signal
import os
from urllib.parse import urlparse

if len(sys.argv) != 3:
    sys.exit(1)

cookiefn = sys.argv[1]
addr = sys.argv[2]
netloc = urlparse(addr).netloc
port = "10001"

serv = 'localhost:{0}'.format(port)
config = '[service]\nclient = yes\naccept = {0}\nconnect = {1}:443\n'.format(serv, netloc)

p1 = subprocess.Popen(["stunnel", "-fd", "0"], stdin=subprocess.PIPE, shell=False)
p1.communicate(input=config.encode('utf-8'))

print("./testhttp_raw {} {} {}\n".format(serv, cookiefn, addr))

subprocess.run(["./testhttp_raw", serv, cookiefn, addr])

p1realPID = subprocess.check_output(["lsof", "-ti", ":{0}".format(port)]).splitlines()[0]
os.kill(int(p1realPID), signal.SIGKILL)