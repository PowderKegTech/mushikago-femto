import ftplib

def anon_login_check(ipaddr, user, password):
  try:
    ftp = ftplib.FTP(ipaddr)
    ftp.set_pasv('true')
    res = ftp.login(user, password)
    return res
    ftp.quit()
  except ftplib.all_errors as e:
    print('Error of FTP information checking:', e)

def ftp_login(ipaddr, user, password):
  try:
    ftp = ftplib.FTP(ipaddr)
    ftp.set_pasv('true')
    res = ftp.login(user, password)
    print(res)
    
    file_list = ftp.nlst(".")
    print(file_list)
    ftp.quit()
  except ftplib.all_errors as e:
    print('Error of FTP information checking:', e)


if __name__ == '__main__':
  res = anon_login_check("10.10.10.3", "anonymous", "anonymous")
  if "230 Login success" in res:
    print("anonymous login successful")
    ftp_login("10.10.10.3", "anonymous", "anonymous")
