from flask import render_template, flash, redirect, url_for, request, Blueprint
from flask_login import login_user, current_user, logout_user

from flaskapp.app import bcrypt, db
from flaskapp.forms import LoginForm, TaskForm, CreateUserForm, UpdateUserForm
from flaskapp.models import User, Task


bp = Blueprint('general', __name__)


@bp.before_request
def before_request():
    if not (current_user.is_authenticated or request.endpoint == 'general.login'):
        return redirect(url_for('general.login'))


@bp.route('/')
def index():
    if current_user.is_admin:
        tasks = Task.query.order_by(Task.date_added.desc())
    else:
        tasks = Task.query.filter_by(is_active=True).order_by(Task.date_added.desc())
    return render_template('general/index.html', title='Задания', tasks=tasks)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('general.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if not user.is_active:
            flash('User is deactivated', 'danger')
            return render_template('general/login.html', title='Login', form=form)
        
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
                    solution=form.solution.data,
                    is_active=form.is_active.data,
                    author=current_user)
        db.session.add(task)
        db.session.commit()
        flash('Task has been created!', 'success')
        return redirect(url_for('general.index'))
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
        task.solution = form.solution.data
        task.is_active = form.is_active.data
        db.session.commit()
        flash('Task has been updated.', 'success')
        return redirect(url_for('general.index'))
    
    if request.method == 'GET':
        form.title.data = task.title
        form.content.data = task.content
        form.solution.data = task.solution
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


@bp.route('/users')
def users():
    if current_user.id != 1:
        flash(f'You are not allowed to go there.', 'error')
        return redirect(url_for('general.index'))
    
    _users = User.query.filter(User.id > 1)
    
    return render_template('general/users.html', title='Users', users=_users)


@bp.route('/add_user', methods=['GET', 'POST'])
def user_add():
    if current_user.id != 1:
        flash(f'You are not allowed to go there.', 'error')
        return redirect(url_for('general.index'))
    
    form = CreateUserForm()
    if form.validate_on_submit():
        user = User(username=form.username.data,
                    password=form.password.data,
                    is_admin=form.is_admin.data,
                    is_active=form.is_active.data,
                    )
        db.session.add(user)
        db.session.commit()
        flash('User has been created!', 'success')
        return redirect(url_for('general.index'))
    return render_template('general/add_user.html', title='Add User', form=form)


@bp.route('/<id>/user_update', methods=['GET', 'POST'])
def user_update(id):
    if current_user.id != 1:
        flash(f'You are not allowed to edit tasks.', 'error')
        return redirect(url_for('general.index'))
    
    user = User.query.get(id)
    
    if not user:
        flash('User not found', 'warning')
        return redirect(url_for('general.index'))
    
    form = UpdateUserForm()
    
    if form.validate_on_submit():
        if form.username.data != user.username and not User.query.filter_by(username=form.username.data).first():
            user.username = form.username.data
        if form.password.data:
            user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.is_active = form.is_active.data
        user.is_admin = form.is_admin.data
        db.session.commit()
        flash('User has been updated.', 'success')
        return redirect(url_for('general.index'))
    
    if request.method == 'GET':
        form.username.data = user.username
        form.password.date = user.password
        form.is_active.data = user.is_active
        form.is_admin.data = user.is_admin
    
    return render_template('general/add_user.html', title='Update User', form=form)


@bp.route('/<id>/user_delete', methods=['POST'])
def user_delete(id):
    if current_user.id != 1:
        flash(f'You are not allowed to go there.', 'error')
        return redirect(url_for('general.index'))
    
    user = User.query.get(id)
    
    if not user:
        flash('user not found', 'warning')
        return redirect(url_for('general.index'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash('User has been deleted.', 'success')
    return redirect(url_for('general.index'))
