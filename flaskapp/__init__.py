from flaskapp.views import general
from flaskapp.app import app

app.register_blueprint(general.bp)
