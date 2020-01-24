from django import forms
#from flask_wtf import FlaskForm
#from wtforms import forms.CharField, PasswordField, BooleanField, SubmitField, forms.MultipleChoiceField, TextAreaField
#from wtforms.validators import DataRequired
#from config import DOC_TYPES, RULE_TYPES, ALERT_TYPES
DOC_TYPES = (('test','test'),('test2','test2'))
RULE_TYPES = (('frequency','frequency'))
ALERT_TYPES = (('email','email'))

class LoginForm(forms.Form):
    user_login = forms.CharField(label="Please enter your login",max_length=50,required=True)
    user_password = forms.CharField(max_length=32, widget=forms.PasswordInput,label="Please enter your password",required=True)

class PassChangeForm(forms.Form):
    old_pass = forms.CharField(max_length=32, widget=forms.PasswordInput,label="Please enter your old password",required=True)
    new_pass1 = forms.CharField(max_length=32, widget=forms.PasswordInput,label="Please enter your new password",required=True)
    new_pass2 = forms.CharField(max_length=32, widget=forms.PasswordInput,label="Please repeat your new password",required=True)

class RuleForm(forms.Form):
    name = forms.CharField(label="Please enter rule name",required=True)
    type = forms.MultipleChoiceField(choices=RULE_TYPES, label="Please enter rule type",required=True)
    index = forms.CharField(initial='filebeat-*', label="Please enter index name",required=True)
    num_events = forms.CharField(initial={'num_events': '1'}, label="Please enter num events",required=True)
    timeframe = forms.CharField(initial={'timeframe': '1'}, label="Please enter time frame",required=True)
    timeframe2 = forms.MultipleChoiceField(initial='timeframe2', choices=(('seconds:', 'seconds'), ('minutes:', 'minutes'), ('hours:', 'hours'), ('days:', 'days'), ('weeks:', 'weeks')),required=True)
    filter = forms.MultipleChoiceField(initial='filter', choices=DOC_TYPES, label="Please enter filter type",required=True)
    filter2 = forms.CharField(initial={'filter2':'Your Search...'}, label="Please enter filter query",required=True)
    alert = forms.MultipleChoiceField(initial='alert', choices=ALERT_TYPES, label="Please enter alert type",required=True)
    email = forms.CharField(initial={'email':'email@domain.com'},label="Please enter emails addresses",required=True)
    saving_button = SubmitField(label='Save rule')
    goback_button = SubmitField(label='Go Back')

class RulesList(forms.Form):
    rules_list = forms.MultipleChoiceField(initial='rules_list', choices=[],label='rules_list',required=True)
    edit_button = SubmitField(label='Edit rule')
    del_button = SubmitField(label='Delete rule')

class TextEditForm(forms.Form):
    text = forms.CharField(widget=forms.TextareaTextAreaField(attr={"rows": 20, "cols": 50}), required=True)
    saving_button = SubmitField(label='Save')
    goback_button = SubmitField(label='Go Back')
