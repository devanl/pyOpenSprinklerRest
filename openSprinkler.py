import requests
import logging
import colorlog

class OpenSprinkler:
  def __init__(self, hostname, log=None):
    if log is None:
      self.log = logging.getLogger(self.__class__.__name__)
    else:
      self.log = log.getChild(self.__class__.__name__)
    
    self.log.debug('Creating OpenSprinkler object')
    self.hostname = hostname


if __name__ == "__main__":

  handler = logging.StreamHandler()
  handler.setFormatter(colorlog.ColoredFormatter(
                       '%(log_color)s%(levelname)s:%(name)s:%(message)s'))

  log = colorlog.getLogger('Open Sprinkler Example')
  log.addHandler(handler)
  log.setLevel(logging.DEBUG)

  log.info('Open Sprinkler Example')

  os_device = OpenSprinkler('192.168.1.11', log=log)
