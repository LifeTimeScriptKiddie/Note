
```
import ftplib

def download_ftp_data(ip_address):
    ftp = ftplib.FTP(ip_address)

    ftp.login()

    print (f'current directory :{ftp.pwd()}')

    ftp.cwd('/documents')  # update per location

    print ('Files:')
    files=ftp.dir()
    
    print (files)

    for file in ftp.nlst():
        print(f'Downloading {file}...')
        ftp.retrbinary(f'RETR {file}', open(file, 'wb').write)

    ftp.quit()
ip_address = input('Enter IP address of the FTP Server: ')
download_ftp_data(ip_address)

```