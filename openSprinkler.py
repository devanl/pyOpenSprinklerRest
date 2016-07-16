import requests
from hashlib import md5
import logging
import colorlog

STATUS_SUCCESS = 1

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
    my_args = ['rsn', 'rbt', 'en', 'rd', 're']
    my_longhand = {'reset_all':'rsn',
                   'reboot':'rbt',
                   'enable':'en',
                   'rain_delay':'rd',
                   'remote_extension':'re'}

    def __init__(self, p):
      self.parent = p
      self.my_args.extend(self.my_longhand.keys())

    def __setattr__(self, name, value):
      if name in self.my_args:
        if name in self.my_longhand.keys():
          name = self.my_longhand[name]
        self.parent._json_get('cv', {name:value})
      else:
        super().__setattr__(name, value)

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
    requests_str = "http://%s/%s/?pw=%s" % (self.hostname, 
                                            path,
                                            self.password)

    if variables:
      for k,v in variables.items():
        requests_str += '&' + str(k) + '=' + str(v)

    r = requests.get(requests_str) 

    self.log.debug('GET %s status: %d', requests_str, r.status_code)
    if r.status_code != 200:
      raise ValueError('Failed GET request with status %d.', r.status_code)

    retval = r.json()
    if 'result' in retval and retval['result'] != STATUS_SUCCESS:
      raise ValueError('Failure response (%d):%s', 
                       retval['result'], 
                       STATUS_CODES[retval['result']])

    return retval

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

  log.info('Setting rain delay for 1 hour')
  os_device.cv.rain_delay = 1

  print(os_device.jc)

  log.info('Setting rain delay to 0')
  os_device.cv.rain_delay = 0

  print(os_device.jc)

