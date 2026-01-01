from quart_wtf import QuartForm
from wtforms import StringField, SubmitField, SelectField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import PasswordInput

class SDNCredForm(QuartForm):
        
    ctr_opts=[('ubnt','Ubiquiti UniFi Network Server'), ('omd','TP-Link Omada Controller')]

    controller = SelectField(label='Choose Network Controller', choices=ctr_opts, validators=[DataRequired()])

    fqdn = StringField('Controller FQDN', validators=[DataRequired(), Length(max=80)])
    uname = StringField('Username', validators=[DataRequired(), Length(max=80)])
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

    submit = SubmitField('Add SDN Crendentials')