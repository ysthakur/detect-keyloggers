from ftplib import FTP
import smtplib
from time import sleep
import io
import sys

email = "lhacs223@gmail.com"
password = "ghrd hvsm akvj wxxj"

if "smtp" in sys.argv:
    smtp_server = smtplib.SMTP("smtp.gmail.com", 25)
    smtp_server.starttls()
    smtp_server.login(email, password)

    try:
        while True:
            sleep(5)
            smtp_server.sendmail(
                email,
                email,
                f"From: {email}\n"
                "Subject: Testing\n"
                "Blah blah blah blah blah lorem ipsum dolor sit amet",
            )
    except KeyboardInterrupt:
        smtp_server.quit()


if "ftp" in sys.argv:
    ftp = FTP("eu-central-1.sftpcloud.io")
    ftp.login(
        user="e21e6df9459e419986f8bf77779b163d",
        passwd="29HyetXq0REOVoIJfWz5OsBuTNrdZXD6",
    )
    while True:
        sleep(5)
        ftp.storbinary("STOR foo.txt", io.BytesIO(b"testing"))
