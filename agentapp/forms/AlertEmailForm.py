from quart_wtf import QuartForm
from wtforms import StringField, SubmitField, SelectField, PasswordField, RadioField, IntegerField
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import PasswordInput

class AlertEmailForm(QuartForm):
        
    tls_opts=[(True,'Enabled'), (False,'Disabled')]

    tls_enabled = RadioField(label='Enable TLS', choices=tls_opts, validators=[DataRequired()])

    smtp_host = StringField('SMTP Host', validators=[DataRequired()])
    smtp_port = IntegerField('SMTP Port', validators=[DataRequired()])
    smtp_user = StringField('SMTP User', validators=[DataRequired()])
    smtp_sender = StringField('SMTP Sender', validators=[DataRequired()])
    password = PasswordField(
        'Password',
        widget=PasswordInput(),
        validators=[
            DataRequired(),
            EqualTo('password_confirm', message='')
        ]
    )
    password_confirm = PasswordField(
        'Confirm Password',
        widget=PasswordInput(),
        validators=[
            DataRequired()
        ]
    )

    submit = SubmitField('Add SMTP Crendentials')