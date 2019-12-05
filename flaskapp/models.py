from datetime import datetime

from flask_login import UserMixin

from flaskapp.app import db, login_manager, bcrypt


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    tasks = db.relationship('Task', backref='author', lazy=True)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        hashed_pw = bcrypt.generate_password_hash(kwargs.get('password')).decode('utf-8')
        self.password = hashed_pw
    
    def __repr__(self):
        return f"User('{self.username}', '{self.is_admin}')"


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_added = db.Column(db.DateTime, nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    link = db.Column(db.String(120), unique=True)
    is_active = db.Column(db.Boolean, default=False)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.date_added = datetime.now()
        self.link = str(int(self.date_added.timestamp() * 1e6))
    
    def __repr__(self):
        return f"Task('{self.title}', '{self.date_added}', '{self.is_active}')"
