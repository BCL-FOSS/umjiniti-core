from quart_wtf import QuartForm
from wtforms import SubmitField, StringField, TextAreaField
from wtforms.validators import DataRequired, Length

class MCPConfigForm(QuartForm):

    server = StringField('MCP Server', validators=[DataRequired(), Length(min=10, max=80)])
    submit = SubmitField('Submit')