from flask import render_template, url_for, redirect, request, flash, g, session
from flask_login import login_user, logout_user, login_required, current_user
from elastalertgui import app, login_manager, logger
from models import User, RuleObj
from .forms import LoginForm, PassChangeForm, RuleForm, RulesList, TextEditForm
from config import ELASTALERT_PATH, DATABASE_PATH, MAIN_CONFIG, RULES_PATH, BACKUP_PATH
import os
import time
import datetime
import sqlite3
import hashlib
import yaml
import shutil

# DB
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def update_db(query, args=()):
    cur = get_db().execute(query, args)
    get_db().commit()
    cur.close()

@app.before_request
def before_request():
    g.user = current_user

# Hashing
def generate_password_hash(pw):
    pw = str(pw)
    pw_hash = hashlib.sha224(pw).hexdigest()
    return pw_hash

def check_password_hash(pw_to_check,pw_hash_from_db):
    pw_to_check_hash = generate_password_hash(pw_to_check)
    if pw_to_check_hash == pw_hash_from_db:
        return True
    else:
        return False

# LM
@login_manager.user_loader
def load_user(user_id):
    user_row = query_db('select * from user where user_id = ?', [user_id], one=True)
    new_user = User(user_row['user_id'],user_row['username'],user_row['pw_hash'])
    return new_user

# File operations
def list_files(_dir):
    files = os.listdir(_dir)
    return files

def parse_yaml(_file):
    with open(_file) as stream:
        try:
            result = yaml.load(stream)
        except yaml.YAMLError as exc:
            logger.error('Error parsing yaml file'+str(exc), exc_info=True)
    return result

def backup_file(_file):
    _bck_file = os.path.basename(_file)+'.'+datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M')
    try:
        shutil.copy(_file, BACKUP_PATH+_bck_file)
    except:
        logger.error('Error during file backup.', exc_info=True)
        raise ValueError('Error during file backup.')

    return _bck_file

def save_file(_file,_data):
    try:
        with open(_file, 'w') as f:
            f.write(_data)
    except:
        logger.error('Error saving file', exc_info=True)

def save_rule(_file,_data):
    with open(_file, 'w+') as stream:
        for key,value in _data.items():
            if str(key) == 'filter':
                try:
                    stream.write('filter:\n'+'- query:\n'+'    query_string:\n'+'       query: \''+str(value)+'\'\n')
                except:
                    logger.error('Error writing: '+str(key)+': '+str(value)+'\n', exc_info=True)
            elif str(key) == 'alert':
                try:
                    stream.write('alert:\n'+'- "email"\n')
                except:
                    logger.error('Error writing: '+str(key)+': '+str(value)+'\n', exc_info=True)
            elif str(key) == 'email':
                try:
                    stream.write('email:\n'+'- '+'"'+str(value)+'"\n')
                except:
                    logger.error('Error writing: '+str(key)+': '+str(value)+'\n', exc_info=True)
            elif ': ' in str(value):
                try:
                    stream.write(str(key)+': \n'+'  '+str(value)+'\n')
                except:
                    logger.error('Error writing: '+str(key)+': '+str(value)+'\n', exc_info=True)
            elif str(key) == 'saving_button' or str(key) == 'reading_button' or str(key) == 'goback_button':
                try:
                    stream.write('\n')
                except:
                    logger.error('Error writing: '+str(key)+': '+str(value)+'\n', exc_info=True)
            else:
                try:
                    stream.write(str(key)+': '+str(value)+'\n')
                except:
                    logger.error('Error writing: '+str(key)+': '+str(value)+'\n', exc_info=True)

def delete_rule(_file):
    try:
        os.remove(_file)
    except:
        logger.error('Error deleting file', exc_info=True)

# Login route
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user is not None and g.user.is_authenticated:
        return redirect(url_for('overview'))

    form = LoginForm()
    if request.method == 'POST' and form.validate():
        user_row = query_db('select * from user where username = ?',[form.user_login.data], one=True)
        if user_row is None:
            logger.warn('No such user in DB')
            flash('No such user in DB')
            return redirect('/login')
        else:
            user_id = user_row['user_id']
            username = user_row['username']
            password = user_row['pw_hash']
            if check_password_hash(form.user_password.data,password):
                logger.info('Login sucessfull')
                flash('Login sucessfull')
                user_obj = User(user_id,username,password)
                login_user(user_obj)
                return redirect('/overview')
            else:
                logger.warn('Password incorrect')
                flash('Password incorrect')
                return redirect('/login')

    return render_template('login.html', title='Login', form=form)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    logger.info('User logout')
    flash('You were logged out')
    return redirect(url_for('login'))

# Overview
@app.route('/overview')
@login_required
def overview():
    try:
        files = list_files(RULES_PATH)
    except:
        logger.error('Cannot access rules directory.')
    files_no_ex = []
    for x in range(len(files)):
        #remove extension
        _temp = os.path.splitext(files[x])[0]
        files_no_ex.append(_temp)

    return render_template('overview.html', files=files_no_ex)

# Rules main page
@app.route('/rules_list', methods=['GET', 'POST'])
@login_required
def rules_list():
    form = RulesList()
    files = list_files(RULES_PATH)
    # create coices
    cat = []
    for x in range(len(files)):
        #remove extension
        file_name_noex = os.path.splitext(files[x])[0]
        cat.append((x,file_name_noex))

    form.rules_list.choices = cat

    if request.method == 'POST' and form.edit_button.data:
        name = dict(form.rules_list.choices)[form.rules_list.data]
        return redirect(url_for('edit_rule', name=name))
    elif request.method == 'POST' and form.del_button.data:
        name = dict(form.rules_list.choices)[form.rules_list.data]
        rule_filename = RULES_PATH+name+'.yaml'
        delete_rule(rule_filename)
        return redirect(url_for('rules_list'))
    return render_template('rules_list.html', form=form)

@app.route('/edit_rule/<name>', methods=['GET', 'POST'])
@login_required
def edit_rule(name):
    rule_obj = RuleObj()
    form = TextEditForm()
    rule_filename = RULES_PATH+name+'.yaml'

    if request.method == 'GET':
        try:
            with open(rule_filename, 'r') as f:
                file_content = f.read()
        except:
            logger.error('Error reading rule file')

        form.text.data = file_content
        return render_template('edit_rule.html', form=form)

    elif request.method == 'POST' and form.goback_button.data:
        return redirect(url_for('rules_list'))

    elif request.method == 'POST' and form.saving_button.data and form.validate():
        try:
            _bck_name = backup_file(rule_filename)
        except:
            flash('Can\'t make backup of the rule file. Stopping oprations.')
            logger.error('Can\'t make backup of the rule file. Stopping oprations.')
            return redirect(url_for('rules_list'))

        save_file(rule_filename,form.text.data)
        flash('Created backup of the rulefile in backup folder. '+rule_filename+' updated.')
        return redirect(url_for('rules_list'))


@app.route('/add_rule', methods=['GET', 'POST'])
@login_required
def add_rule():
    rule_obj = RuleObj()
    form = RuleForm()

    if request.method == 'POST' and form.validate():
        form.populate_obj(rule_obj)
        list_of_vars = vars(rule_obj)

        #Merge timeframe and timeframe2 fields from the form to one var
        list_of_vars['timeframe'] = list_of_vars['timeframe2']+' '+list_of_vars['timeframe']
        list_of_vars.pop('timeframe2')

        #Merge filters fileds
        list_of_vars['filter'] = '_type: '+list_of_vars['filter']+' AND '+'"'+list_of_vars['filter2']+'"'
        list_of_vars.pop('filter2')

        _filename = RULES_PATH+str(list_of_vars['name'])+'.yaml'
        save_rule(_filename,list_of_vars)
        flash('Rule added')
        return redirect(url_for('rules_list'))
    return render_template('add_rule.html', form=form)

# Config
@app.route('/main_config', methods=['GET', 'POST'])
@login_required
def main_config():
    form = TextEditForm()

    if request.method == 'GET':
        try:
            with open(MAIN_CONFIG, 'r') as f:
                file_content = f.read()
        except:
            logger.error('Can\'t read main config file')

        form.text.data = file_content
        return render_template('main_config.html', form=form)

    elif request.method == 'POST' and form.goback_button.data:
        return redirect(url_for('overview'))

    elif request.method == 'POST' and form.saving_button.data and form.validate():
        try:
            _bck_name = backup_file(MAIN_CONFIG)
        except:
            flash('Can\'t make backup of the main config file. Stopping oprations.')
            logger.error('Can\'t make backup of the main config file. Stopping oprations.')
            return redirect(url_for('overview'))

        save_file(MAIN_CONFIG,form.text.data)
        flash('Created backup of the main config file in backup folder. '+MAIN_CONFIG+' updated.')
        return redirect(url_for('overview'))


# Profile
@app.route('/change_pass',methods=['GET', 'POST'])
@login_required
def change_pass():
    form = PassChangeForm()
    if request.method == 'POST' and form.validate():
        user_row = query_db('select * from user where username = ?',[g.user.name], one=True)
        if user_row is None:
            flash('Abnormal error - no user in session?')
            return redirect('/login')
        else:
            if not check_password_hash(form.old_pass.data,user_row['pw_hash']):
                flash('Wrong old pass')
                return redirect('change_pass')
            elif form.new_pass1.data != form.new_pass2.data:
                flash('Passwords not matched')
                return redirect(url_for('change_pass'))
            else:
                user_new_pass = generate_password_hash(form.new_pass1.data)
                update_db('update user set pw_hash = ? where username = ?', [user_new_pass, g.user.name])
                flash('Password updated')
                return redirect(url_for('overview'))

    return render_template('change_pass.html', form=form)
