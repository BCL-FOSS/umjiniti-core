from quart_wtf import QuartForm
from wtforms import StringField, SubmitField, RadioField, SelectField, TextAreaField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length
from utils.Util import Util
from wtforms.widgets import PasswordInput

class APIKeyGenForm(QuartForm):

    ctr_opts=[('umj-api-wflw','umjiniti Workflow'), ('umj-api-chat','umjiniti NetChat')]

    api = SelectField(label='Choose Service', choices=ctr_opts, validators=[DataRequired()])
    
    submit = SubmitField('Generate API Key')