from flask import current_app, url_for
from flask_mail import Message
from extensions import mail, db, socketio
from flask_socketio import emit
from models import Notification

def send_notification_email(user, subject, body):
    """Send an email notification to the given user."""
    msg = Message(subject,
                  sender=current_app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[user.email])
    msg.body = body
    mail.send(msg)

def notify_user(user, message, link=None, notif_type="general", send_email=False, subject=None):
    """
    Sends a notification to the user by:
      - Creating a Notification record in the database.
      - Emitting a real-time update via Socket.IO.
      - Optionally sending an email notification.
    
    Parameters:
      user: The User object to notify.
      message: The notification message.
      link: Optional URL for related content.
      notif_type: Type of notification (default is "general").
      send_email: Boolean flag to indicate if an email should be sent.
      subject: Optional subject for the email; if not provided, a default is used.
    """
    # Create and store the notification record
    notification = Notification(user_id=user.id, message=message, link=link, type=notif_type)
    db.session.add(notification)
    db.session.commit()

    # Emit real-time notification update via Socket.IO
    socketio.emit(f'new_notification_{user.id}', {
        "message": message,
        "link": link,
        "timestamp": notification.timestamp.strftime('%Y-%m-%d %H:%M'),
        "type": notif_type
    }, namespace='/notifications')

    # Optionally send an email notification
    if send_email:
        email_subject = subject if subject is not None else f"New Notification: {notif_type}"
        email_body = f"{message}\n\nView it here: {link if link else 'Login to check your notifications.'}"
        send_notification_email(user, email_subject, email_body)

