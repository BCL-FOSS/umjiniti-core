from quart_wtf import QuartForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from wtforms.widgets import PasswordInput
from utils.Util import Util
from wtforms.validators import ValidationError

class RegisterForm(QuartForm):
    uname = StringField('Username', validators=[DataRequired(), Length(min=5, max=15)])
    password = PasswordField(
        'Password',
        widget=PasswordInput(),
        validators=[
            DataRequired(),
            EqualTo('password_confirm', message=''),
            Length(min=15, max=50)
        ]
    )
    password_confirm = PasswordField(
        'Confirm Password',
        widget=PasswordInput(),
        validators=[
            DataRequired(),
            Length(min=15, max=50)
        ]
    )

    submit = SubmitField("Create Account")