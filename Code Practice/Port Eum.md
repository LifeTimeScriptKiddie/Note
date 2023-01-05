```
#!/usr/bin/env python3
import socket
import sys

def port_scan(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        if result == 0:
            print (f"Port {port} is open")
        s.close()
    except Exception as e:
        print (e)

def main ():
    if len(sys.argv) !=2:
        print ("Usage: python port_scan.py [host]")
        sys.exit(1)

    host= sys.argv[1]
    with open("port_scan.txt", "W") as f:
	    for port in range (1, 65535):
	        result=port_scan(host, port)
	        f.write(result)
if __name__ == "__main__":
    main()

```

