from flaskapp.app import manager
from flaskapp import *
import os


if __name__ == '__main__':
    print(os.getcwd())
    os.chdir('flaskapp')
    manager.run()
