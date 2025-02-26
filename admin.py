from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from models import User  # ensure your User model is imported correctly
from extensions import db
from flask_login import login_required, current_user
from notifications import notify_user

# Create a blueprint for admin routes with a URL prefix /admin
admin_bp = Blueprint('admin', __name__, template_folder='templates', url_prefix='/admin')

@admin_bp.route('/users', methods=['GET'])
def view_users():
    """Retrieve and display all user information."""
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@admin_bp.route('/users/search', methods=['GET', 'POST'])
def search_users():
    """Search for users by any part of their username or email."""
    if request.method == 'POST':
        search_term = request.form.get('search_term', '')
        users = User.query.filter(
            (User.username.ilike(f'%{search_term}%')) |
            (User.email.ilike(f'%{search_term}%'))
        ).all()
        return render_template('admin_users.html', users=users, search_term=search_term)
    return render_template('admin_search.html')

@admin_bp.route('/users/notifications', methods=['GET', 'POST'])
def update_notifications():
    """
    Update notifications for a single user (if 'user_id' is provided and not "all") or for all users.
    The form should include a 'notification' field and optionally a 'user_id' field.
    """
    if request.method == 'POST':
        notification = request.form.get('notification', '')
        user_id = request.form.get('user_id')
        if user_id and user_id != "all":
            user = User.query.get(user_id)
            if user:
                # Assuming notifications is a field for a single notification message.
                user.notifications = notification
                db.session.commit()
                flash(f"Notification updated for user {user.username}.", "success")
            else:
                flash("User not found.", "danger")
        else:
            # Update notification for all users
            users = User.query.all()
            for user in users:
                user.notifications = notification
            db.session.commit()
            flash("Notification updated for all users.", "success")
        return redirect(url_for('admin.view_users'))
    return render_template('admin_update_notifications.html')

@admin_bp.route('/api/users', methods=['GET'])
def api_get_users():
    """Return user info in JSON format."""
    users = User.query.all()
    users_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at.isoformat(),
        'password_hash': user.password_hash,
        'followers': [f.follower_id for f in user.followers],
        'notifications': [n.message for n in user.notifications_list],
        'following': [f.followed_id for f in user.following]
    } for user in users]
    return jsonify(users_data)

@admin_bp.before_request
def require_admin():
    from flask import abort
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)

@admin_bp.route('/notify', methods=['GET', 'POST'])
@login_required
def notify_users():
    if request.method == 'POST':
        subject = request.form.get('subject', 'Notification')
        message = request.form.get('message', '')
        user_id = request.form.get('user_id', '')
        if user_id:
            user = User.query.get(user_id)
            if user:
                notify_user(user, subject, message)
                flash(f"Notification sent to {user.username}.", "success")
            else:
                flash("User not found.", "danger")
        else:
            # Send notification to all users
            users = User.query.all()
            for user in users:
                notify_user(user, subject, message)
            flash("Notification sent to all users.", "success")
        return redirect(url_for('admin.notify_users'))
    return render_template('admin_notify.html')
