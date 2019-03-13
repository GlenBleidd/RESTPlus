from flask_restplus import Api
from flask import Blueprint

from .main.controller.controller import api as user_ns
from .main.controller.controller import api_auth as auth_ns

blueprint = Blueprint('api', __name__)

api = Api(blueprint,
          title='BOOP FLASK RESTPLUS APIWITH JWT',
          version='1.0',
          description='boop flask restplus web service'
          )

api.add_namespace(user_ns, path='/user')
api.add_namespace(auth_ns)
