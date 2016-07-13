import requests
from hashlib import md5
import logging
import colorlog

STATUS_CODES = {1:'Success',
                2:'Unauthorized (e.g. missing password or password is incorrect)',
                3:'Mismatch (e.g. new password and confirmation password do not match)',
                16:'Data Missing (e.g. missing required parameters)',
                17:'Out of Range (e.g. value exceeds the acceptable range)',
                18:'Data Format Error (e.g. provided data does not match required format)',
                19:'RF code error (e.g. RF code does not match required format)',
                32:'Page Not Found (e.g. page not found or requested file missing)',
                48:'Not Permitted (e.g. cannot operate on the requested station)'}

class OpenSprinkler:
  class CV:
    def __init__(self, parent):
      self.parent = parent

    my_args = ['rsn', 'rbt', 'en', 'rd', 're']

    def __setattr__(self, name, value):
      if name in self.my_args:
        self.parent._json_get('cv', {name:value}

  def __init__(self, hostname, password, log=None):
    if log is None:
      self.log = logging.getLogger(self.__class__.__name__)
    else:
      self.log = log.getChild(self.__class__.__name__)
    
    self.log.debug('Creating OpenSprinkler object')
    self.hostname = hostname
    self.password = md5(password.encode('utf-8')).hexdigest()

    self.cv = self.CV(self)

  def _json_get(self, path, variables=None):
    requests_str = 'http://' +
                   self.hostname +
                   '/' +
                   path +
                   '?pw=' +
                   self.password

    if variables:
      for k,v in variables.iteritems():
        requests_str += '&' + k + '=' + v

    r = requests.get(requests_str) 

    self.log.debug('GET status: %d', r.status_code)
    if r.status_code != 200:
      raise ValueError('Failed GET request with status %d.', r.status_code)

    return r.json()

  @property
  def jc(self):
    return self._json_get('jc')


if __name__ == "__main__":
  import sys

  handler = logging.StreamHandler()
  handler.setFormatter(colorlog.ColoredFormatter(
                       '%(log_color)s%(levelname)s:%(name)s:%(message)s'))

  log = colorlog.getLogger('Open Sprinkler Example')
  log.addHandler(handler)
  log.setLevel(logging.DEBUG)

  log.info('Open Sprinkler Example')

  if len(sys.argv) < 3:
    exit(1)
  
  hostname = sys.argv[1]
  password = sys.argv[2]
  os_device = OpenSprinkler(hostname, password, log=log)

  print(os_device.jc)
