from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy
db = SQLAlchemy()

# Followers Table (Many-to-Many)
followers_table = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), primary_key=True),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), primary_key=True),
)

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bio = db.Column(db.Text, nullable=True)
    profile_picture_url = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(10), nullable=False, default="User")

    def __init__(self, **kwargs):
        """Ensure new users get a default role."""
        super().__init__(**kwargs)
        if not self.role:
            self.role = "User"

    def set_role(self):
        """Assigns the 'Head' role if the user is the owner email."""
        if self.email == "bb2010ng@gmail.com":
            self.role = "Head"
        elif not self.role:
            self.role = "User"
        db.session.commit()

    def is_head(self):
        return self.role == "Head"

    def is_admin(self):
        return self.role in ["Head", "Admin"]

    # Relationship with Story (One-to-Many)
    stories = db.relationship('Story', back_populates='user', lazy=True)

    # Relationship for Following Users
    following = db.relationship(
        "User",
        secondary=followers_table,
        primaryjoin=(followers_table.c.follower_id == id),
        secondaryjoin=(followers_table.c.followed_id == id),
        backref=db.backref("followers", lazy="dynamic"),
        lazy="dynamic",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def follow(self, user):
        """Follow another user."""
        if not self.is_following(user):
            self.following.append(user)
            db.session.commit()

    def unfollow(self, user):
        """Unfollow a user."""
        if self.is_following(user):
            self.following.remove(user)
            db.session.commit()

    def is_following(self, user):
        """Check if the user is following another user."""
        return self.following.filter(followers_table.c.followed_id == user.id).count() > 0

    def __repr__(self):
        return f"<User {self.username}>"


class Story(db.Model):
    __tablename__ = "stories"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    genres = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=True)
    cover_image = db.Column(db.String(255), nullable=True)
    published = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes_count = db.Column(db.Integer, default=0)

    # Relationships
    user = db.relationship("User", back_populates="stories")
    comments = db.relationship("Comment", backref="story", lazy=True)
    likes = db.relationship("Like", backref="story", lazy=True)

    def update_likes_count(self):
        """Update the total number of likes on this story."""
        self.likes_count = Like.query.filter_by(story_id=self.id).count()
        db.session.commit()


class Like(db.Model):
    __tablename__ = "likes"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)
    story_id = db.Column(db.Integer, db.ForeignKey("stories.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class LikeSettings(db.Model):
    __tablename__ = "like_settings"

    id = db.Column(db.Integer, primary_key=True)
    head_likes = db.Column(db.Integer, default=5, nullable=False)
    admin_likes = db.Column(db.Integer, default=3, nullable=False)
    user_likes = db.Column(db.Integer, default=1, nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey("stories.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship("User", backref="comments")
    notifications = db.relationship("Notification", back_populates="comment", cascade="all, delete-orphan")


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey("comments.id", ondelete="CASCADE"), nullable=True)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    comment = db.relationship("Comment", back_populates="notifications")


class DiaryEntry(db.Model):
    __tablename__ = "diary_entries"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)


class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_story = db.Column(db.Boolean, default=False)



