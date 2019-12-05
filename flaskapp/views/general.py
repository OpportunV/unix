from flask import render_template, flash, redirect, url_for, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required

from flaskapp.app import bcrypt
from flaskapp.forms import LoginForm
from flaskapp.models import User


bp = Blueprint('general', __name__)


@bp.before_request
def before_request():
    if not (current_user.is_authenticated or request.endpoint == 'general.login'):
        return redirect(url_for('general.login'))


@bp.route('/')
def index():
    return render_template('general/index.html', title='Main Page')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('general.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('general.index'))
        
        flash('Login Unsuccessful. Please check username and password', 'danger')
    
    return render_template('general/login.html', title='Login', form=form)


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('general.login'))


# @bp.route('/account')
# @login_required
# def account():
#     return render_template('account.html', title='Account')
