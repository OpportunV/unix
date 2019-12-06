from flask import render_template, flash, redirect, url_for, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required

from flaskapp.app import bcrypt, db
from flaskapp.forms import LoginForm, TaskForm
from flaskapp.models import User, Task


bp = Blueprint('general', __name__)


@bp.before_request
def before_request():
    if not (current_user.is_authenticated or request.endpoint == 'general.login'):
        return redirect(url_for('general.login'))


@bp.route('/')
def index():
    if current_user.is_admin:
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(is_active=True)
    return render_template('general/index.html', title='Задания', tasks=tasks)


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


@bp.route('/new', methods=['GET', 'POST'])
def new():
    if not current_user.is_admin:
        flash(f'You are not allowed to add tasks.', 'error')
        return redirect(url_for('general.index'))
    
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(title=form.title.data,
                    content=form.content.data,
                    is_active=form.is_active.data,
                    author=current_user)
        db.session.add(task)
        db.session.commit()
        flash('Task has been created!', 'success')
        return redirect(url_for('general.index', link=task.link))
    return render_template('general/new.html', title='New Task', form=form)


@bp.route('/<link>/update', methods=['GET', 'POST'])
def task_update(link):
    if not current_user.is_admin:
        flash(f'You are not allowed to edit tasks.', 'error')
        return redirect(url_for('general.index'))
    
    task = Task.query.filter(Task.link == link).first()
    
    if not task:
        flash('task not found', 'warning')
        return redirect(url_for('general.index'))
    
    form = TaskForm()
    
    if form.validate_on_submit():
        task.title = form.title.data
        task.content = form.content.data
        task.is_active = form.is_active.data
        db.session.commit()
        flash('Task has been updated.', 'success')
        return redirect(url_for('general.index', link=task.link))
    
    if request.method == 'GET':
        form.title.data = task.title
        form.content.data = task.content
        form.is_active.data = task.is_active
    
    return render_template('general/new.html', title='Update Task', form=form)


@bp.route('/<link>/delete', methods=['POST'])
def task_delete(link):
    if not current_user.is_admin:
        flash(f'You are not allowed to delete tasks.', 'error')
        return redirect(url_for('general.index'))
    
    task = Task.query.filter(Task.link == link).first()
    
    if not task:
        flash('task not found', 'warning')
        return redirect(url_for('general.index'))
    
    db.session.delete(task)
    db.session.commit()
    
    flash('Task has been deleted.', 'success')
    return redirect(url_for('general.index'))

# @bp.route('/account')
# @login_required
# def account():
#     return render_template('account.html', title='Account')
