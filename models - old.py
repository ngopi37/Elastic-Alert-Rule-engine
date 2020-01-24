from django.db import models

class User(models.Model):
    user_id = models.CharField(max_length=60)
    name = models.CharField(max_length=60)
    password = models.CharField(max_length=20)
    active = models.BooleanField() 
    
    def is_authenticated():
        return True
        #return true if user is authenticated, provided credentials

    def is_active():
        return True
        #return true if user is activte and authenticated

    def is_annonymous():
        return False
        #return true if annon, actual user return false

    def get_id(self):
        try:
            return user_id  # python 2
        except NameError:
            return self.user_id # python 3

    def __repr__(self):
        return self.name

class RuleObj(models.Model):
    
    def __init__(self,name = '',type = '',index = '',num_events = '',
                timeframe2 = '', timeframe = '', filter = '', filter2 = '',
                alert = '',email = ''):
        self.name = name
        self.type = type
        self.index = index
        self.num_events = num_events
        self.timeframe2 = timeframe2
        self.timeframe = timeframe
        self.filter = filter
        self.filter2 = filter2
        self.alert = alert
        self.email = email
