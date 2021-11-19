import smtplib

hostname = '127.0.0.1'
sender_email = 'YOUR_USER@writer.htb'
port = 25
receiver_email = 'YOUR_USER@writer.htb'
message = ' Send email to john '

try:
	server = smtplib.SMTP(hostname,port)
	server.ehlo()
	server.sendmail(sender_email, receiver_email, message)
except Exception as e:
	print(e)
finally:
	server.quit()
