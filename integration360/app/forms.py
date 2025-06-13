from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, TextAreaField, FileField, PasswordField, SelectMultipleField
from wtforms.validators import DataRequired, Length, ValidationError
import re
from wtforms.validators import Optional






def validate_string(form, field):
    if not isinstance(field.data, str) or not re.match(r'^[a-zA-Z0-9\s\-\'",.!?]*$', field.data):
        raise ValidationError('Only string values are allowed!')

def validate_file(form, field):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif','pdf', 'docx','txt'}
    if field.data:
        filename = field.data.filename.lower()
        if not ('.' in filename and filename.rsplit('.', 1)[1] in allowed_extensions):
            raise ValidationError('Only PNG, JPG, and GIF files are allowed!')


class KnowledgeForm(FlaskForm):
    type_choices = [
        ('', 'Select a value'),
        ('KB', 'KB'), 
        ('casestudy', 'Case Study')
    ]
    type = SelectField('Type', choices=type_choices, validators=[DataRequired()])

    industry_choices = [
        ('', 'Select a value'),
        ('insurance', 'Insurance'),
        ('ota', 'OTA'),
        ('ecom', 'E-commerce'),
        ('investments', 'Investments'),
        ('government', 'Government'),
        ('gaming', 'Gaming'),
        ('lending', 'Lending'),
        ('partnership', 'Partnership'),
        ('Others', 'Others'),

    ]
    industry = SelectField('Industry', choices=industry_choices, validators=[DataRequired()])

    checkout_type_choices = [
        ('', 'Select a value'),
        ('standard', 'Standard'),
        ('custom', 'Custom'),
        ('s2s', 'S2S'),
        ('hosted', 'Hosted')
    ]
    checkout_type = SelectField('Checkout Type', choices=checkout_type_choices, validators=[DataRequired()])

    product_name_choices = [
        ('PG', 'PG'),
        ('route', 'Route'),
        ('recurring', 'Recurring'),
        ('subscriptions', 'Subscriptions'),
        ('smart_collect', 'Smart Collect'),
        ('optimizer', 'Optimizer')
    ]
    product_name = SelectMultipleField('Product Name', choices=product_name_choices, validators=[DataRequired()])

    content_type_choices = [
        ('', 'Select a value'),
        ('key_features', 'Key Features'),
        ('prerequisites', 'Prerequisites'),
        ('walkthrough', 'Walkthrough'),
        ('integration_steps', 'Integration Steps'),
        ('best_practices', 'Best Practices'),
        ('error_scenarios', 'Error Scenarios'),
        ('end-to-end', 'End-to-End')
    ]
    content_type = SelectField('Content Type', choices=content_type_choices, validators=[DataRequired()])

    attachment = FileField('Attachment', validators=[validate_file])
    comments = TextAreaField('Comments')
    submit = SubmitField('Submit')

# Login Form
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class TicketDetailsForm(FlaskForm):
    ticket_id = SelectField('Ticket ID', choices=[], validators=[DataRequired()])
    cf_merchant_id = StringField('Merchant ID', render_kw={'readonly': True})
    cf_contact_number = StringField('Contact Number', render_kw={'readonly': True})
    cf_product = StringField('Product', render_kw={'readonly': True})
    cf_platform = StringField('Platform', render_kw={'readonly': True})
    cf_platform_item = StringField('Platform Item', render_kw={'readonly': True})
    cf_checkout = StringField('Checkout', render_kw={'readonly': True})
    cf_issue_category = StringField('Issue Category', render_kw={'readonly': True})
    cf_issue_sub_category = StringField('Issue Sub Category', render_kw={'readonly': True})
    issue_description = TextAreaField('Issue Description', validators=[DataRequired()])
    cf_agent_category = StringField('Agent Category', validators=[DataRequired()])
    cf_agent_sub_category = StringField('Agent Subcategory', validators=[DataRequired()])
    resolution = TextAreaField('Resolution', validators=[DataRequired()])
    workaround = TextAreaField('Workaround', validators=[DataRequired()])
    comments_text = TextAreaField('Comments')
    submit = SubmitField('Submit Ticket')





class QueryForm(FlaskForm):
    product = SelectField('Product', choices=[('', 'Select')] + [('PG', 'PG'),
        ('route', 'Route'),
        ('recurring', 'Recurring'),
        ('subscriptions', 'Subscriptions'),
        ('smart_collect', 'Smart Collect'),
        ('optimizer', 'Optimizer')
        ], validators=[DataRequired()])
    query = TextAreaField('Query', validators=[DataRequired()])
    resolution = TextAreaField('Resolution')
    workaround = TextAreaField('Workaround')
    submit = SubmitField('Submit')
