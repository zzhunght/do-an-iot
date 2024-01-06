import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email(attack_type = ''):
    sender_email = "hung18072002ht@gmail.com"
    receiver_email = "n20dccn105@student.ptithcm.edu.vn"
    password = "tpyguwqzuvpszhzz"
    # Tạo thông điệp email
    subject = "Cảnh báo bị tấn công"
    body = "Server của bạn đang bị tấn công : " + attack_type
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    message.attach(MIMEText(body, "plain"))
    # Kết nối đến máy chủ SMTP
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()

    try:
        # Đăng nhập vào tài khoản email
        server.login(sender_email, password)
        # Gửi email
        server.sendmail(sender_email, receiver_email, message.as_string())
        print("Gửi email cảnh báo thành công!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Đóng kết nối
        server.quit()

