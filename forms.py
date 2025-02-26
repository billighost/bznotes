from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
class BaseForm(FlaskForm):
    class Meta:
        csrf = True
        csrf_secret = 'your-csrf-secret-key'

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    remember = BooleanField('Remember Me')
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# You can use SignUpForm as the registration form.
class SignUpForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[
        DataRequired(), Length(min=8),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password')

# Alias RegisterForm to SignUpForm for convenience.
RegisterForm = SignUpForm

class NoteForm(FlaskForm):
    title = StringField('Thought Title', validators=[DataRequired(), Length(max=120)])
    content = TextAreaField('Neural Patterns', validators=[DataRequired()])
class DiaryForm(FlaskForm):
    content = TextAreaField('Neural Patterns', validators=[DataRequired()])

# Form for requesting a password reset email
class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])



class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password", 
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")]
    )
    submit = SubmitField("Reset Password")
