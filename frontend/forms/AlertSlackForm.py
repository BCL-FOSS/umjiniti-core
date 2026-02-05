from quart_wtf import QuartForm
from wtforms import StringField, SubmitField, SelectField, PasswordField, RadioField, IntegerField
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import PasswordInput

class AlertSlackForm(QuartForm):

    slack_token = StringField('Slack Auth Token', validators=[DataRequired()])
    slack_channel_id = StringField('Slack Channel ID', validators=[DataRequired()])

    submit = SubmitField('Add Slack Crendentials')