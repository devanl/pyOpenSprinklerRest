import requests
from hashlib import md5
import logging
import colorlog
import datetime

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

class FieldDescriptor(object):
  def __init__(self, tag, type):
    self._tag = tag
    self._type = type

class FieldGetDescriptor(FieldDescriptor):
  def getAsType(self, data):
    if type(self._tag) is list:
      return self._type({yk: data[yk] for yk in self._tag})
    return self._type(data[self._tag])

class FieldSetDescriptor(FieldDescriptor):
  def setAsType(self, data):
    return {self._tag: self._type(data)}

def OSDateTime(ts):
  if ts == 0:
    return False
  return datetime.datetime.fromtimestamp(ts)

def SunTime(minutes):
  if minutes == 0:
    return None
  now = datetime.datetime.now()
  midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
  return midnight + datetime.timedelta(days=1) - datetime.timedelta(minutes=minutes)

def IPAddress(ip):
  return '%d.%d.%d.%d' % (ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)

def Stations(stat):
  print('stations(%r)' % (stat,))
  retval = []
  for field in stat:
    for i in range(8):
      retval.append((field & (1<<i))!=0)
  return tuple(retval)

def Nop(val):
  return val

def RainDelaySet(dt):
  if not dt:
    return 0
  now = datetime.datetime.now()
  return int((dt - now).total_seconds() / 3600)


class GetSetObj(object):
  my_get_args = {}
  my_set_args = {}

  json_get = None
  json_set = None

  def __init__(self, p):
    self.parent = p

  def __getattr__(self, name):
    if name in self.my_get_args.keys():
      data = self.parent._json_get(self.json_get)
      return self.my_get_args[name].getAsType(data)

  def __setattr__(self, name, value):
    if name in self.my_set_args.keys():
      data = self.my_set_args[name].setAsType(value)
      self.parent._json_get(self.json_set, data)
    else:
      super().__setattr__(name, value)


class Controller(GetSetObj):
  json_get = 'jc'
  json_set = 'cv'

  '''
  - devt: Device time (epoch time). This is always the local time.
  - nbrd: Number of 8-station boards (including main controller).
  - en: Operation enable bit.
  - rd: Rain delay bit (1: rain delay is currently in effect; 0: no rain delay).
  - rs: Rain sensor status bit (1: rain is detected from rain sensor; 0: no rain detected).
  - rdst: Rain delay stop time (0: rain delay no in effect; otherwise: the time when rain delay is over).
  - loc: Location string.
  - wtkey: Wunderground API key.
  - sunrise: Today’s sunrise time (minutes from midnight).
  - sunset: Today’s sunset time (minutes from midnight).
  - eip: external IP, calculated as (ip[3]<<24)+(ip[2]<<16)+(ip[1]<<8)+ip[0]
  - lwc: last weather call/query (epoch time)
  - lswc: last successful weather call/query (epoch time)
  - sbits: Station status bits. Each byte in this array corresponds to an 8-station board and represents the bit field (LSB).
    For example, 1 means the 1st station on the board is open, 192 means the 7th and 8th stations are open.
  - ps: Program status data: each element is a 3-field array that stores the [pid,rem,start] of a station, where
    pid is the program index (0 means non), rem is the remaining water time (in seconds), start is the start time.
    If a station is not running (sbit is 0) but has a non-zero pid, that means the station is in the queue waiting to run.
  - lrun: Last run record, which stores the [station index, program index, duration, end time] of the last run station.
  '''
  my_get_args = {'device_time': FieldGetDescriptor('devt', OSDateTime),
                 'board_count': FieldGetDescriptor('nbrd', int),
                 'enable': FieldGetDescriptor('en', bool),
                 'rain_delay': FieldGetDescriptor('rd', bool),
                 'rain_sensor': FieldGetDescriptor('rs', bool),
                 'rain_resume': FieldGetDescriptor('rdst', OSDateTime),  # TODO: figure out what this data type is
                 'location': FieldGetDescriptor('loc', str),
                 'weather_id': FieldGetDescriptor('wtkey', str),
                 'sunrise': FieldGetDescriptor('sunrise', SunTime),
                 'sunset': FieldGetDescriptor('sunset', SunTime),
                 'external_ip': FieldGetDescriptor('eip', IPAddress),
                 'last_weather': FieldGetDescriptor('lwc', OSDateTime),
                 'last_good_weather': FieldGetDescriptor('lswc', OSDateTime),
                 'station_status': FieldGetDescriptor('sbits', Stations),
                 'program_status': FieldGetDescriptor('ps', Nop), # TODO: figure out this data type
                 'last_run': FieldGetDescriptor('lrun', Nop)} # TODO: figure out this data type

  '''
  - rsn: Reset all stations (i.e. stop all stations immediately, including those waiting to run). Binary value.
  - rbt: Reboot the controller. Binary value.
  - en: Operation enable. Binary value.
  - rd: Set rain delay time (in hours). A value of 0 turns off rain delay.
  - re: Set the controller to remote extension mode (so that stations on this controller can be used as remote stations).
  '''
  my_set_args = {'reset_all': FieldSetDescriptor('rsn', int),
                 'reboot': FieldSetDescriptor('rbt', int),
                 'enable': FieldSetDescriptor('en', int),
                 'rain_delay': FieldSetDescriptor('rd', RainDelaySet),
                 'remote_extension': FieldSetDescriptor('re', int)}


def OSTZ(tz):
  tz = (tz - 48) / 4.0
  return datetime.timedelta(hours=tz)

def IPArray(key_list, ip):
  retval = "%s" % (ip[key_list[0]],)
  for key in key_list[1:]:
    retval += ".%s" % (ip[key],)

  return retval

IPSTATIC_KEYS = ['ip1', 'ip2', 'ip3', 'ip4']
def IPStatic(ip):
  return IPArray(IPSTATIC_KEYS, ip)

IPGATEWAY_KEYS = ['gw1', 'gw2', 'gw3', 'gw4']
def IPGateway(ip):
  return IPArray(IPGATEWAY_KEYS, ip)

IPNTP_KEYS = ['ntp1', 'ntp2', 'ntp3', 'ntp4']
def IPNTP(ip):
  return IPArray(['ntp1', 'ntp2', 'ntp3', 'ntp4'], ip)

HP_KEYS = ['hp0', 'hp1']
def HPInt(port):
  return (port['hp1']<<8) + port['hp0']

class Options(GetSetObj):
  json_get = 'jo'

  '''
  - fwv: Firmware version (215 means Firmware 2.1.5).
  - fwm: Firmware minor version (increments with minor revisions to the firmware)
  - tz: Time zone (floating point time zone value * 4 + 48). For example, GMT+0:00 is 48; GMT-4:00 is 32, GMT+9:30 is 86.
        Acceptable range is 0 to 96.
  - ntp: Use NTP sync. Binary value.
  - dhcp: Use DHCP. Binary value.
  - ip{1,2,3,4}: Static IP (ignored if dhcp=1).
  - gw{1,2,3,4}: Gateway (router) IP (ignored if dhcp=1).
  - ntp{1,2,3,4}: NTP server IP (ignored if ntp=0).
  - hp{0,1}: The lower and upper bytes of the HTTP port number. So http_port=(hp1<<8)+hp0.
  - hwv: Hardware version.
  - hwt: Hardware type. Values are as follows: 0xAC = AC power type, 0xDC = DC power type, 0x1A = Latching type.
  - ext: Number of expansion boards (not including the main controller).
  - sdt: Station delay time (in seconds). Acceptable range is -60 to +60 seconds, in steps of seconds, or -59 to 59 minutes.
  - mas/mas2: Master stations 1 and 2 (a value of 0 means none). Note that this firmware supports up to 2 master stations.
  - mton/mton2: Master 1 and 2 on delay time. Acceptable range is 0 to 60.
  - mtof/mtof2: Master off delay time. Acceptable range is -60 to 60.
  - urs: Use rain sensor. Binary value.
  - rso: Rain sensor type. Binary value. 0: normally closed; 1: normally open.
  - wl: Water level (i.e. % Watering). Acceptable range is 0 to 250.
  - den: Operation enable bit. Binary value.
  - ipas: Ignore password. Binary value.
  - devid: Device ID.
  - con/lit/dim: LCD contrast / backlight / dimming values.
  - bst: Boost time changes the boost converter duration for DC type (in milli-seconds). Acceptable range is 0 to 1000.
  - uwt: Weather adjustment method. 0: manual adjustment; 1: Zimmerman method. Water restriction information for
         California is encoded in the last bit.
  - lg: Enable logging.
  - fpr{0,1}: flow pulse rate (scaled by 100) lower/upper byte. The actual flow pulse rate is ((fpr1<<8)+fpr0)/100.0
  - re: Remote extension mode
  - dexp/mexp: Detected/maximum number of zone expansion boards (-1 means cannot auto-detect).
  '''
  my_get_args = {'firmware_version': FieldGetDescriptor('fwv', int),
                 'firmware_minor': FieldGetDescriptor('fwm', int),
                 'time_zone': FieldGetDescriptor('tz', OSTZ),
                 'use_ntp': FieldGetDescriptor('ntp', bool),
                 'use_dhcp': FieldGetDescriptor('dhcp', bool),
                 'ip': FieldGetDescriptor(IPSTATIC_KEYS, IPStatic),
                 'gateway': FieldGetDescriptor(IPGATEWAY_KEYS, IPGateway),
                 'ntp_server': FieldGetDescriptor(IPNTP_KEYS, IPNTP),
                 'http_port': FieldGetDescriptor(HP_KEYS, HPInt),
                 'hw_version': FieldGetDescriptor('hwv', int),
                 'hw_type': FieldGetDescriptor('hwt', int),
                 'expander_cnt': FieldGetDescriptor('ext', int),
                 'station_delay': FieldGetDescriptor('sdt', int),
                 'master_1': FieldGetDescriptor('mas', int),
                 'master_2': FieldGetDescriptor('mas2', int),
                }


class OpenSprinkler:

  def __init__(self, hostname, password, log=None):
    if log is None:
      self.log = logging.getLogger(self.__class__.__name__)
    else:
      self.log = log.getChild(self.__class__.__name__)
    
    self.log.debug('Creating OpenSprinkler object')
    self.hostname = hostname
    self.password = md5(password.encode('utf-8')).hexdigest()

    self.controller = Controller(self)
    self.options = Options(self)

  def _json_get(self, path, variables=None):
    requests_str = "http://%s/%s/?pw=%s" % (self.hostname, 
                                            path,
                                            self.password)

    if variables:
      for k,v in variables.items():
        requests_str += '&' + str(k) + '=' + str(v)

    r = requests.get(requests_str) 

    #self.log.debug('GET %s status: %d', requests_str, r.status_code)
    if r.status_code != 200:
      raise ValueError('Failed GET request with status %d.', r.status_code)

    retval = r.json()
    if 'result' in retval and retval['result'] != STATUS_SUCCESS:
      raise ValueError('Failure response (%d):%s', 
                       retval['result'], 
                       STATUS_CODES[retval['result']])

    return retval


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

  log.info('Get "controller" fields:')
  for prop in Controller.my_get_args.keys():
    print('%s: %r' % (prop, getattr(os_device.controller, prop)))

  log.info('Get "options" fields:')
  for prop in Options.my_get_args.keys():
    print('%s: %r' % (prop, getattr(os_device.options, prop)))

  log.info('Setting rain delay for 1 hour')
  os_device.controller.rain_delay = datetime.datetime.now() + datetime.timedelta(hours=4)
  log.info('Rain delay: %r', os_device.controller.rain_delay)
  log.info('Rain resume: %r', os_device.controller.rain_resume)

  log.info('Setting rain delay to 0')
  os_device.controller.rain_delay = 0
  log.info('Rain delay: %r', os_device.controller.rain_delay)
  log.info('Rain resume: %r', os_device.controller.rain_resume)

