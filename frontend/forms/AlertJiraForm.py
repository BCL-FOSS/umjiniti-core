from quart_wtf import QuartForm
from wtforms import StringField, SubmitField, SelectField, PasswordField, RadioField, IntegerField
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import PasswordInput

class AlertJiraForm(QuartForm):

    cloud_id = StringField('Jira Cloud ID', validators=[DataRequired()])
    email = IntegerField('Jira Email', validators=[DataRequired()])
    auth_token = StringField('Jira Auth Token', validators=[DataRequired()])

    submit = SubmitField('Add Jira Crendentials')