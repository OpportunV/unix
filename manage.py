from flaskapp.app import manager
from flaskapp import *
import os


if __name__ == '__main__':
    os.chdir('flaskapp')
    manager.run()
