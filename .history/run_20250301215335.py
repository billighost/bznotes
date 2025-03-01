import os
import secrets
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, redirect, url_for, flash, request, jsonify, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from config import Config
from forms import LoginForm, RegisterForm, NoteForm, ResetPasswordForm, RequestResetForm, DiaryForm
from models import db, User, Story, Like, Comment, Notification, DiaryEntry, Note, followers_table
from flask import current_app
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask import abort
from waitress import serve


app = Flask(__name__)
app.config['SECRET_KEY'] = 'tentententententententententen'
csrf = CSRFProtect(app)

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(dotenv_path):
    print("✅ .env file found! Loading...")
    load_dotenv(dotenv_path)
else:
    print("⚠️ .env file NOT found!")

# ✅ Ensure .env is loaded
dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    print("⚠️ .env file NOT found!")

# ✅ Debugging: Check if variables are loaded
print("MAIL_USERNAME:", os.getenv("MAIL_USERNAME"))
print("MAIL_PASSWORD:", "✔ Loaded" if os.getenv("MAIL_PASSWORD") else "❌ NOT LOADED")
print("SECRET_KEY:", "✔ Loaded" if os.getenv("SECRET_KEY") else "❌ NOT LOADED")

# Ensure Flask App Uses the Loaded Secret Key
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# Debugging: Confirm SECRET_KEY is loaded inside Flask
print("FLASK SECRET_KEY:", "✔ Loaded" if app.config["SECRET_KEY"] else "❌ NOT LOADED")

# Now, initialize the serializer safely
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


# Load environment variables from .env file
load_dotenv()

# ✅ Initialize Flask App
app = Flask(__name__)
app.config.from_object(Config)

# ✅ Initialize Database
db.init_app(app)

# ✅ Initialize Flask-Migrate
migrate = Migrate(app, db)

# ✅ Ensure migrations run correctly
with app.app_context():
    db.create_all()

# ✅ Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Load email settings
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

# Debugging logs
print("MAIL_SERVER:", app.config["MAIL_SERVER"])
print("MAIL_PORT:", app.config["MAIL_PORT"])
print("MAIL_USE_TLS:", app.config["MAIL_USE_TLS"])
print("MAIL_USERNAME:", app.config["MAIL_USERNAME"])
print("MAIL_PASSWORD:", "✔ Loaded" if app.config["MAIL_PASSWORD"] else "❌ NOT LOADED")



# ✅ Initialize Flask-Mail
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

UPLOAD_FOLDER = "static/images/story_covers"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_login import login_required, current_user
from flask_socketio import SocketIO, emit
from models import db, Notification, User
from datetime import datetime
socketio = SocketIO(app)


from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_login import login_required, current_user
from flask_socketio import SocketIO
from models import db, Notification

# ---------------- SEND NOTIFICATIONS ----------------
def send_notification(user_id, message):
    """Creates a new notification and sends it via SocketIO"""
    notification = Notification(user_id=user_id, message=message)
    db.session.add(notification)
    db.session.commit()
    socketio.emit(f'notify_{user_id}', {'id': notification.id, 'text': message, 'timestamp': notification.timestamp.strftime('%b %d, %Y')}, namespace='/notifications')

@app.route("/privacy-policy")
def privacy_policy():
    """
    Display the Privacy & Policy page.
    """
    return render_template("privacy_policy.html")



# ---------------- FETCH NOTIFICATIONS ----------------
@app.route("/get_notifications")
@login_required
def get_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    
    return jsonify({
        "notifications": [{"id": n.id, "message": n.message, "is_read": n.is_read} for n in notifications],
        "unread_count": unread_count
    })


@app.route("/notifications")
@login_required
def notifications_page():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    return render_template("notifications.html", notifications=notifications)



# ---------------- VIEW A NOTIFICATION ----------------
@app.route("/view_notification/<int:notification_id>")
@login_required
def view_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    # Mark as read
    notification.is_read = True
    db.session.commit()

    return render_template("view_notification.html", notification=notification)


# ----------------- REAL-TIME EVENTS ------------------
@socketio.on("connect", namespace="/notifications")
def connect():
    print(f"User {current_user.id} connected to notifications.")

@socketio.on("disconnect", namespace="/notifications")
def disconnect():
    print(f"User {current_user.id} disconnected from notifications.")

@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    """Marks all notifications as read."""
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({"success": True})

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Allow users to request a password reset via email."""
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        user = User.query.filter_by(email=email).first()

        if user:
            # ✅ Generate token
            token = serializer.dumps(user.email, salt="password-reset")

            # ✅ Send reset email
            send_reset_email(user, token)

            flash('📩 Reset instructions sent to your email!', 'success')
            return redirect(url_for('login'))
        else:
            flash('⚠️ Email not found!', 'danger')

    return render_template('forgot_password.html')

# # Ensure LikeSettings exists in the DB
# @app.before_first_request
# def create_settings():
#     if LikeSettings.query.first() is None:
#         settings = LikeSettings(head_likes=5, admin_likes=3, user_likes=1)
#         db.session.add(settings)
#         db.session.commit()

@app.route('/refresh_likes/<int:story_id>', methods=['GET'])
def refresh_likes(story_id):
    story = Story.query.get_or_404(story_id)
    return jsonify({'likes': story.likes_count})


def send_reset_email(user, token):
    """Send a password reset email using credentials from .env file."""
    reset_url = url_for("reset_password", token=token, _external=True)
    
    msg = Message(
        "🔑 Password Reset Request",
        sender=os.getenv("MAIL_USERNAME"),  # ✅ Use email from .env
        recipients=[user.email]
    )

    msg.body = f"""Hello {user.username},

You requested a password reset. Click the link below to reset your password:

{reset_url}

If you did not request this, please ignore this email.

Best,  
BZNotes Team
"""

    mail.send(msg)

# ✅ User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===========================
# ⚡ MISSING ROUTES ADDED ⚡
# ===========================

@app.route("/explore")
@login_required
def explore():
    """Show public stories and notes from other users."""
    public_stories = Story.query.filter_by(published=True).order_by(Story.date_posted.desc()).all()
    return render_template("explore.html", public_stories=public_stories)

@app.route("/followings")
@login_required
def followings():
    """Show a list of users the current user follows."""
    followed_users = current_user.following.all()
    return render_template("followings.html", followed_users=followed_users)

@app.route("/followers")
@login_required
def followers():
    """Show a list of users who follow the current user."""
    followers_list = current_user.followers.all()
    return render_template("followers.html", followers=followers_list)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Allow users to update their account settings."""
    if request.method == "POST":
        new_email = request.form.get("email")
        if new_email:
            current_user.email = new_email
            db.session.commit()
            flash("Email updated successfully!", "success")
    return render_template("settings.html")


@app.route("/following_list")
@login_required
def following_list():
    followed_users = User.query.join(followers_table, followers_table.c.followed_id == User.id) \
                               .filter(followers_table.c.follower_id == current_user.id) \
                               .all()
    return render_template("following_list.html", followed_users=followed_users)

@app.route('/search_users', methods=['GET'])
@login_required
def search_users():
    """Search for users based on input"""
    query = request.args.get('query', '').strip()
    
    if query:
        users = User.query.filter(User.username.ilike(f"%{query}%"), User.id != current_user.id).all()
    else:
        users = User.query.filter(User.id != current_user.id).all()

    return jsonify([{"id": user.id, "username": user.username} for user in users])

@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    """Follow a user"""
    user = User.query.get_or_404(user_id)
    
    if user == current_user:
        return jsonify({'error': 'You cannot follow yourself!'}), 400

    if current_user.is_following(user):
        return jsonify({'message': 'Already following'}), 200

    current_user.follow(user)
    return jsonify({'message': f'You are now following {user.username}'}), 200

@app.route('/unfollow/<int:user_id>', methods=['POST'])
@login_required
def unfollow_user(user_id):
    """Unfollow a user"""
    user = User.query.get_or_404(user_id)

    if not current_user.is_following(user):
        return jsonify({'message': 'Not following this user'}), 200

    current_user.unfollow(user)
    return jsonify({'message': f'You have unfollowed {user.username}'}), 200

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/edit_story/<int:story_id>", methods=["GET", "POST"])
@login_required
def edit_story(story_id):
    story = Story.query.get_or_404(story_id)

    if story.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for("my_stories"))

    if request.method == "POST":
        action = request.form.get("action")  # Check if "Post" or "Save Draft"
        story.title = request.form.get("title")
        story.content = request.form.get("content")

        # ✅ Handling cover image upload
        if "cover_image" in request.files:
            file = request.files["cover_image"]
            if file and allowed_file(file.filename):
                filename = secure_filename(f"story_{story.id}_{secrets.token_hex(8)}.png")
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                story.cover_image = f"/{UPLOAD_FOLDER}/{filename}"  # ✅ Save new path in DB

        if action == "post":
            story.published = True
            flash("Story posted successfully!", "success")
        else:
            story.published = False  # ✅ Keep it as a draft
            flash("Draft saved successfully!", "success")

        db.session.commit()
        return redirect(url_for("my_stories"))

    return render_template("edit_story.html", story=story)


@app.route("/request_reset", methods=["GET", "POST"])
def request_reset():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash("Password reset instructions sent!", "info")
        return redirect(url_for("login"))

    return render_template("request_reset.html", form=form)

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    db.session.delete(current_user)
    db.session.commit()
    flash("Your account has been deleted.", "info")
    return redirect(url_for("home"))

@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/dashboard")
@login_required
def dashboard():
    notes = Note.query.filter_by(user_id=current_user.id).all()  # ✅ Ensure correct query
    return render_template("dashboard.html", notes=notes)


from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models import db, User, Story, Like, Comment

# ------------------- User Profile Page -------------------
@app.route("/user_profile/<int:user_id>")
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template("user_profile.html", user=user)

# ------------------- Like a Story -------------------
from models import db, Story, Like, LikeSettings

@app.route('/like_story/<int:story_id>', methods=['POST'])
@login_required
def like_story(story_id):
    story = Story.query.get_or_404(story_id)
    like = Like.query.filter_by(user_id=current_user.id, story_id=story.id).first()
    
    # Get the Like Settings
    settings = LikeSettings.query.first()
    if not settings:
        settings = LikeSettings(head_likes=5, admin_likes=3, user_likes=1)
        db.session.add(settings)
        db.session.commit()

    # Determine the user's like weight
    like_weight = settings.user_likes  # Default for normal users
    if current_user.is_head():
        like_weight = settings.head_likes
    elif current_user.is_admin():
        like_weight = settings.admin_likes

    if like:
        # If already liked, remove the like and subtract weighted value
        db.session.delete(like)
        story.likes_count -= like_weight
        liked = False
    else:
        # Add new like and apply weighted value
        new_like = Like(user_id=current_user.id, story_id=story.id)
        db.session.add(new_like)
        story.likes_count += like_weight
        liked = True

    # Ensure likes count never goes below zero
    if story.likes_count < 0:
        story.likes_count = 0

    db.session.commit()

    return jsonify({'likes': story.likes_count, 'liked': liked})


@app.before_first_request
def ensure_like_settings():
    if LikeSettings.query.first() is None:
        settings = LikeSettings(head_likes=5, admin_likes=3, user_likes=1)
        db.session.add(settings)
        db.session.commit()

# ------------------- Add a Comment -------------------
@app.route("/add_comment/<int:story_id>", methods=["POST"])
@login_required
def add_comment(story_id):
    story = Story.query.get_or_404(story_id)

    data = request.get_json()
    content = data.get("content")

    if not content:
        return jsonify({"error": "Comment cannot be empty"}), 400

    # Save comment to database
    new_comment = Comment(user_id=current_user.id, story_id=story_id, content=content)
    db.session.add(new_comment)
    db.session.commit()

    # Send notification
    if current_user.id != story.user_id:
        send_notification(story.user_id, f"{current_user.username} commented on your story: {story.title}")

    return jsonify({
        "id": new_comment.id,
        "username": current_user.username,
        "profile_picture_url": current_user.profile_picture_url or "/static/default-avatar.png",
        "content": new_comment.content,
        "created_at": new_comment.created_at.strftime('%b %d, %Y'),
    })

    new_comment = Comment(user_id=current_user.id, story_id=story_id, content=content)
    db.session.add(new_comment)
    db.session.commit()

    return jsonify({
        "id": new_comment.id,
        "username": current_user.username,
        "profile_picture_url": current_user.profile_picture_url or "/static/default-avatar.png",
        "content": new_comment.content,
        "created_at": new_comment.created_at.strftime('%b %d, %Y'),
    })




@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))  # Redirect if already logged in

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Ensure all fields are filled
        if not username or not email or not password or not confirm_password:
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        # Check if user exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Username or email already exists!", "danger")
            return redirect(url_for("register"))
        if form.validate_on_submit():
            user = User(
                username=form.username.data,
                email=form.email.data,
                role="Head" if form.email.data == "bb2010ng@gmail.com" else "User"
            )
        # Create and add user to the database
        new_user = User(username=username, email=email)
        new_user.set_password(password)  # Hash the password
        db.session.add(new_user)


        try:
            db.session.commit()
            flash("Registration successful! You can now log in.", "success")
            send_notification(new_user.id, '''🚀 Welcome to B'z Notes Pro! Start your journey today!
Whether it is:
1.writing diaries,notes,journals e.t.c
2.Writing stories and posting them 
P.S you don't have to write stories at once you can just save them and come back to it and when you are done you can post it for other users to read and enjoy😍😍.
3.Writing and editing your profile
4.A well designed graphical interface
5.And as an extra tip A CALENDAR🎉🎉

So pump yourself get ready to start writing,reading or do whatever suits you.Here at B'z notes we have it all

Love,B'z notes pro team                                                                                                                                                                  ''')  # ✅ Send notification
            return redirect(url_for("login"))
        except:
            db.session.rollback()
            flash("An error occurred. Try again!", "danger")

    return render_template("register.html", form=form)



@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session.permanent = True  # Keep user logged in
            login_user(user, remember=True)  # Remember session
            if user.email == "bb2010ng@gmail.com":
                user.role = "Head"
                db.session.commit()
            send_notification(user.id, '''🎉 You have successfully logged in!
                              
.Get ready to start writing stories and notes(Diary drafts) and if you are the type that loves to read,we got you covered😘
Courtesy:B'z notes team                              ''')  # ✅ Send notification
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)

@app.route("/diary_list")
@login_required
def diary_list():
    entries = DiaryEntry.query.filter_by(user_id=current_user.id).order_by(DiaryEntry.created_at.desc()).all()
    return render_template("diary_list.html", entries=entries)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    bio = request.form.get("bio", "").strip()

    if not bio:
        flash("Bio cannot be empty!", "danger")
        return redirect(url_for("profile"))

    current_user.bio = bio
    db.session.commit()

    flash("Profile updated successfully!", "success")
    send_notification(current_user.id, "✨ You updated your profile!")  # ✅ Send notification
    return redirect(url_for("profile"))

@app.route("/upload_profile_picture", methods=["POST"])
@login_required
def upload_profile_picture():
    if "profile_picture" not in request.files:
        flash("No file selected!", "danger")
        return redirect(url_for("profile"))

    file = request.files["profile_picture"]
    if file.filename == "":
        flash("Invalid file!", "danger")
        return redirect(url_for("profile"))

    # Generate a unique filename
    filename = f"profile_{current_user.id}_{secrets.token_hex(8)}.png"
    file_path = os.path.join("static/images", filename)
    file.save(file_path)

    # Save the new profile picture URL
    current_user.profile_picture_url = f"/static/images/{filename}"
    db.session.commit()

    flash("Profile picture updated!", "success")
    send_notification(current_user.id, "✨ You updated your profile!")  # ✅ Send notification
    return redirect(url_for("profile"))

@app.route("/story_time/<int:story_id>")
@login_required
def story_time(story_id):
    # Get comments for the story
    comments = Comment.query.filter_by(story_id=story_id).order_by(Comment.created_at.desc()).all()
    story = Story.query.get_or_404(story_id)
    likes_count = Like.query.filter_by(story_id=story_id).count()
    comments = Comment.query.filter_by(story_id=story_id).order_by(Comment.created_at.desc()).all()
    csrf_token_value = generate_csrf() 
    return render_template("story_time.html", story=story, likes_count=likes_count, comments=comments, csrf_token=csrf_token_value)


    print(f"Found Story: {story.title}")  # Debugging
    print(f"Likes: {likes_count}, Comments: {len(comments)}")  # Debugging

     # ✅ Generate CSRF token before passing it
    return render_template("story_time.html", story=story, likes=likes_count, comments=comments)




@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Handles password reset using a token"""
    try:
        email = serializer.loads(token, salt="password-reset", max_age=1800)
    except:
        flash("⚠️ Invalid or expired token.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first_or_404()
    form = ResetPasswordForm()

    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        flash("✅ Password reset successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", form=form)

def send_reset_email(user, token):
    """Sends a password reset email with a secure token"""
    reset_url = url_for("reset_password", token=token, _external=True)

    msg = Message(
        "🔑 Password Reset Request",
        sender=os.getenv("MAIL_USERNAME"),  # ✅ Uses .env email
        recipients=[user.email]
    )

    msg.body = f"""Hello {user.username},

You requested a password reset. Click the link below to reset your password:

{reset_url}

If you did not request this, please ignore this email.

Best,  
BZNotes Team
"""

    mail.send(msg)


@app.route("/calendar")
@login_required
def calendar_page():
    return render_template("calendar.html")

@app.route("/new_story", methods=["GET", "POST"])
@login_required
def new_story():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        genres = request.form.get("genres", "").strip()
        description = request.form.get("description", "").strip()

        # ✅ Debugging Print Statements
        print(f"Title: {title}, Genres: {genres}, Description: {description}")

        if not title or not genres or not description:
            flash("⚠️ Title, Genres, and Description are required!", "danger")
            return redirect(url_for("new_story"))

        try:
            new_story = Story(
                title=title,
                genres=genres,
                description=description,
                user_id=current_user.id
            )
            db.session.add(new_story)
            db.session.commit()
            send_notification(current_user.id, f"📝 You created a new story: {title}")  # ✅ Send notification
            flash("✅ Story created successfully!", "success")
            return redirect(url_for("my_stories"))
        except Exception as e:
            db.session.rollback()
            print("❌ Error creating story:", e)  # ✅ Print the error in console
            flash(f"❌ Error creating story: {str(e)}", "danger")
            return redirect(url_for("new_story"))

    return render_template("new_story.html")


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_head():  # Ensure only Head can delete users
        abort(403)

    user = User.query.get(user_id)
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("users_page"))

    if user.role == "Head":
        flash("You cannot delete the Head user!", "danger")
        return redirect(url_for("users_page"))

    # ✅ First, delete all notifications associated with the user
    Notification.query.filter_by(user_id=user.id).delete()

    # ✅ Now delete the user
    db.session.delete(user)
    db.session.commit()

    flash("User deleted successfully!", "success")
    return redirect(url_for("users_page"))


@app.route("/my_stories")
@login_required
def my_stories():
    """Show only draft stories."""
    stories = Story.query.filter_by(user_id=current_user.id, published=False).order_by(Story.created_at.desc()).all()
    return render_template("my_stories.html", stories=stories)

@app.route("/delete_story/<int:story_id>", methods=["POST"])
@login_required
def delete_story(story_id):
    story = Story.query.get_or_404(story_id)

    if story.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for("my_stories"))

    db.session.delete(story)
    db.session.commit()
    
    flash("Draft deleted successfully!", "success")
    return redirect(url_for("my_stories"))
@app.route("/delete_story/<int:story_id>", methods=["POST"])
@login_required
def delete_entry(DiaryEntry_id):
    entry = DiaryEntry.query.get_or_404(DiaryEntry_id)

    if DiaryEntry.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for("diary_list"))

    db.session.delete(entry)
    db.session.commit()
    
    flash("entry deleted successfully!", "success")
    return redirect(url_for("diary_list"))
@app.route("/delete_story/<int:story_id>", methods=["POST"])
@login_required
def deleted_story(story_id):
    if not current_user.is_head():
        abort(403)  # Forbidden if not Head

    story = Story.query.get_or_404(story_id)
    db.session.delete(story)
    db.session.commit()
    flash("Story deleted!", "success")
    return redirect(url_for("read_stories"))
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired

class NotificationForm(FlaskForm):
    notification = TextAreaField("Notification", validators=[DataRequired()])
    username = StringField("Username (Optional)")
    submit = SubmitField("Send Notification")

@app.route("/notify_users", methods=["GET", "POST"])
@login_required
def notify_users():
    if not current_user.is_admin():
        abort(403)  # Prevent unauthorized users
    
    form = NotificationForm()

    if form.validate_on_submit():
        notification_text = form.notification.data
        username = form.username.data.strip()

        if username:
            user = User.query.filter_by(username=username).first()
            if user:
                new_notification = Notification(user_id=user.id, message=notification_text)
                db.session.add(new_notification)
                db.session.commit()
                flash(f"Notification sent to {username}!", "success")
            else:
                flash("User not found!", "danger")
        else:
            users = User.query.all()
            for user in users:
                new_notification = Notification(user_id=user.id, message=notification_text)
                db.session.add(new_notification)
            db.session.commit()
            flash("Notification sent to all users!", "success")

        return redirect(url_for("notify_users"))

    return render_template("notify_users.html", form=form)



@app.route("/users", methods=["GET"])
@login_required
def users_page():
    if not current_user.is_head():
        abort(403)

    users = User.query.all()
    return render_template("users.html", users=users)


@app.route("/make_admin/<int:user_id>", methods=["POST"])
@login_required
def make_admin(user_id):
    if not current_user.is_head():
        abort(403)

    user = User.query.get_or_404(user_id)
    user.role = "Admin"
    db.session.commit()
    flash(user.username + " is now an Admin!", "success")
    return redirect(url_for("users_page"))

from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField
from wtforms.validators import DataRequired

class DetermineLikesForm(FlaskForm):
    head_likes = IntegerField("Head Likes", validators=[DataRequired()])
    admin_likes = IntegerField("Admin Likes", validators=[DataRequired()])
    user_likes = IntegerField("User Likes", validators=[DataRequired()])
    submit = SubmitField("Save Changes")

from flask import render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import login_required, current_user
from models import db, LikeSettings  # Ensure you have a model for storing like multipliers

@app.route("/determine_likes", methods=["GET", "POST"])
@login_required
def determine_likes():
    if not current_user.is_head():
        return "Forbidden", 403

    settings = LikeSettings.query.first()

    if request.method == "POST":
        settings.head_likes = int(request.form["head_likes"])
        settings.admin_likes = int(request.form["admin_likes"])
        settings.user_likes = int(request.form["user_likes"])
        db.session.commit()
        flash("Like settings updated!", "success")
        return redirect(url_for("determine_likes"))

    return render_template("determine_likes.html", settings=settings)

@app.before_first_request
def create_settings():
    if LikeSettings.query.first() is None:
        settings = LikeSettings(head_likes=5, admin_likes=3, user_likes=1)
        db.session.add(settings)
        db.session.commit()






from sqlalchemy.sql import func

from sqlalchemy import func

@app.route("/read_stories")
@login_required
def read_stories():
    sort_option = request.args.get("sort", "newest")

    # Query to get published stories with like count
    stories_query = (
        db.session.query(
            Story, func.count(Like.id).label("likes_count")
        )
        .outerjoin(Like)
        .filter(Story.published == True)  # ✅ Ensures only published stories
        .group_by(Story.id)
    )

    # Sorting Logic
    if sort_option == "most_liked":
        stories_query = stories_query.order_by(func.count(Like.id).desc())
    elif sort_option == "recommendations":
        stories_query = stories_query.order_by(Story.created_at.desc()).limit(10)
    else:  # Default: Newest first
        stories_query = stories_query.order_by(Story.created_at.desc())

    stories = stories_query.all()

    return render_template("read_stories.html", stories=[s[0] for s in stories])  # ✅ Extract Story objects properly



@app.route("/new_diary", methods=["GET", "POST"])
@login_required
def new_diary():
    form = DiaryForm
    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not content:
            flash("Content cannot be empty", "danger")
            return redirect(url_for("new_diary"))

        diary_entry = DiaryEntry(content=content, user_id=current_user.id)
        db.session.add(diary_entry)
        db.session.commit()
        flash("Diary entry created successfully!", "success")
        return redirect(url_for("diary_list"))

    return render_template("new_diary.html", form = form)

@app.route("/edit_diary/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit_diary(entry_id):
    entry = DiaryEntry.query.get_or_404(entry_id)
    
    if entry.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for("diary_list"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not content:
            flash("Content cannot be empty!", "danger")
            return redirect(url_for("edit_diary", entry_id=entry_id))

        entry.content = content
        db.session.commit()
        flash("Diary entry updated successfully!", "success")
        return redirect(url_for("diary_list"))

    return render_template("edit_diary.html", entry=entry)

@app.route("/notifications")
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    return render_template("notifications.html", notifications=user_notifications)

@app.route("/about")
def about():
    return render_template("about.html")

@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("500.html"), 500

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', debug=True)

