#!/usr/local/bin/env/bin/python3

from weakref import proxy
import requests
from requests import Response
#import pytest
import time
import datetime as dt
import random
import os
import signal
import ssl
from cryptography import x509;
from cryptography.hazmat.primitives import hashes 
import configparser
import daemon
import syslog

from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.firefox.service import Service as FirefoxService

from webdriver_manager.core.download_manager import WDMDownloadManager
from webdriver_manager.core.http import HttpClient

from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains

from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

import sys
import subprocess
from threading import Thread
from queue import Queue, Empty

import pyotp
import atexit

DEBUG=False
MAX_STEPS=20
SCHEDULE_MODE=True
IPTABLES_MODE=False if not SCHEDULE_MODE else True

PROXY = getattr(os.environ, 'https_proxy', None)
  
WORKING_HOURS = {
  'start': dt.time(7,25),
  'end': dt.time(17,0), #if not DEBUG else dt.time(23,59),
  'randomness': 15*60,
  'weekdays': range(1,5)
} if SCHEDULE_MODE else {
  'start': dt.time(0,0),
  'end': dt.time(0,0),
  'randomness': 0,
  'weekdays': range(0,7)
}

LAST_SEED=int(dt.datetime.combine(dt.date.today(),dt.time(0,0,0)).timestamp())
random.seed(LAST_SEED)

ON_POSIX = 'posix' in sys.builtin_module_names

def delay(seconds=2, min_seconds=1,randomize=True):
    time.sleep(random.randrange(min_seconds,seconds) if randomize and min_seconds < seconds else seconds)

def is_time_between(begin_time, end_time, check_time=None):
    # If check time is not given, default to current UTC time
    check_time = check_time or dt.datetime.now()
    if begin_time < end_time:
        return check_time >= begin_time and check_time <= end_time
    else: # crosses midnight
        return check_time >= begin_time or check_time <= end_time

def should_be_on():
  global LAST_SEED
  if LAST_SEED != int(dt.datetime.combine(dt.date.today(),dt.time(0,0,0)).timestamp()):
    LAST_SEED=int(dt.datetime.combine(dt.date.today(),dt.time(0,0,0)).timestamp())
  random.seed(LAST_SEED)

  return \
    dt.datetime.today().weekday() in WORKING_HOURS['weekdays'] and \
    is_time_between(
        dt.datetime.combine(dt.date.today(),WORKING_HOURS['start']) + dt.timedelta(0,random.randint(0,WORKING_HOURS['randomness'])), 
        dt.datetime.combine(dt.date.today(),WORKING_HOURS['end']) + dt.timedelta(0,random.randint(0,WORKING_HOURS['randomness']))
    )


class CustomHttpClient(HttpClient):

    def get(self, url, params=None, **kwargs) -> Response:
      if PROXY != None:
        proxies = {
          'http': PROXY,
          'https': PROXY,
          #'no_proxy': '*.presidencia.gov.br'
        }
      else:
        proxies = None

      #log("The call will be done with custom HTTP client")
      return requests.get(url, params, proxies=proxies,  **kwargs)


class VPN():
  def __init__(self, host, port, user, pwd, secret, cert, realm):
    self.host = host
    self.port = port
    self.realm = realm
    self.url = 'https://{}:{}'.format(host,port)
    self.user = user
    self.pwd = pwd
    self.secret = secret
    self.cert = cert
    self.otp = pyotp.TOTP(self.secret)

  def inject_jquery(self):
    has_jquery = self.driver.execute_script("return window.jQuery")
    if not has_jquery:
      self.driver.execute_script("""
        var script = document.createElement( 'script' );
        script.type = 'text/javascript';
        script.src = 'https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js';
        document.head.appendChild(script);
      """)
      delay(2, randomize=False)

  def setup_method(self, driver='phantomjs'):

    self.driver = None

    if driver=='phantomjs':
      self.driver = webdriver.PhantomJS(
        executable_path='/opt/phantomjs/bin/phantomjs',
        service_args=['--remote-debugger-port=9001','--remote-debugger-autorun=yes'] if DEBUG else [])
    else:
      chrome_options = webdriver.ChromeOptions()
      chrome_options.add_argument('--headless')
    
      if PROXY != None:
        http_client = CustomHttpClient()
        chrome_options.add_argument('--proxy-server=%s' % PROXY)
      else:
        http_client = CustomHttpClient()
    
      download_manager = WDMDownloadManager(http_client)
      self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager(download_manager=download_manager).install()))
      self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager(download_manager=download_manager).install()))
      self.driver = webdriver.Chrome(service=ChromeService(options=chrome_options,executable_path='/usr/lib/chromium-browser/chromedriver'))

    self.vars = {}
    self.driver.implicitly_wait(5)
    self.driver.set_window_size(1450, 897)
    self.driver.get(self.url)
    self.inject_jquery()
    delay (1, randomize=False)

  
  def teardown_method(self):
    self.driver.close()
    self.driver.service.process.send_signal(signal.SIGTERM) # kill the specific phantomjs child proc
    delay (3)
    self.driver.service.process.send_signal(signal.SIGKILL) # kill the specific phantomjs child proc
    self.driver.quit()

  def find_elements(self, selectors=None):
    res = {}
    self.inject_jquery()
        
    for selector in selectors:
      try:
        my_selector = selector if selector[0] == "$" else "$('{}')".format(selector)
        elements=self.driver.execute_script("return {}".format(my_selector))
        if elements != None and len(elements):
          res[selector] = elements
      except Exception as e:
        print (e)
        pass
        #raise (e)
    
    return res

  def set_elements(self, elements, value):
    # try:
    #   element = WebDriverWait(self.driver,timeout=1).until(EC.element_to_be_clickable(elements))
    # except Exception:
    #   element = elements[0]
    element = elements[0]

    if value != element.get_attribute('value'):
      element.clear()
      element.send_keys(value, Keys.RETURN)
      assert value, element.get_attribute('value')
      return

      if value == element.get_attribute('value'): return

      self.driver.execute_script("arguments[0].focus()", element)
      self.driver.execute_script("arguments[0].value=arguments[1]", element, self.user + "@" + self.realm)

      assert value, element.get_attribute('value')

  def click_elements(self, elements):
    # try:
    #   element = WebDriverWait(self.driver,timeout=1).until(EC.element_to_be_clickable(elements))
    # except Exception:
    #   element = elements[0]
    element = elements[0]
    element.click()
    return

    element.send_keys(Keys.RETURN)

    self.driver.execute_script("arguments[0].focus()", element)
    self.driver.execute_script("arguments[0].click()", element)

    actions = ActionChains(self.driver)
    actions.click(on_element=element)
    
  def login(self):
    try:
      SVPNCOOKIE=self.driver.get_cookie('SVPNCOOKIE')
      if SVPNCOOKIE: 
        if DEBUG: print('got svncookie')
        return SVPNCOOKIE.get('value',None)     
    except Exception:
      pass

    selectors = {
      '#otherTile': False,
      'input[type=email]': False,
      'input[type=password]': False,
      'input[type=tel]': False,
      'input[type=submit]': False
    }

    steps=0
        
    while SVPNCOOKIE is None and steps < MAX_STEPS:
      steps += 1
      if DEBUG: 
        print('Try:', steps,'/', MAX_STEPS)
      
        print (self.driver.title, end='') 
        try:
          print (': ' + list(self.find_elements(['.title','.text-title']).values())[-1][-1].text)
        except Exception as e:
          print()
          pass
      
      res = self.find_elements(
        selectors=selectors.keys()
      )
      if not len(res):
        delay(1,randomize=False)
        continue

      for matched, elements in res.items():
        if not len(elements) or selectors[matched]: continue
        try:
          if matched == 'input[type=email]':
            if (self.user  == elements[0].get_attribute('value')): continue
            self.set_elements(elements,self.user)
            if DEBUG: print("Email")
            # selectors[matched]=True
            
          if matched == 'input[type=password]':
            if (self.pwd == elements[0].get_attribute('value')): continue
            self.set_elements(elements,self.pwd)
            if DEBUG: print("Password")
            # selectors[matched]=True
            forms = self.find_elements({'form': False})
            
          if matched == 'input[type=tel]':
            if (self.otp.now() == elements[0].get_attribute('value')): continue
            self.set_elements(elements,self.otp.now())
            if DEBUG: print("Secret", self.otp.now())
            # selectors[matched]=True
            self.inject_jquery()
            
          if matched == '#otherTile':
            self.click_elements(elements)

            if DEBUG: print("Had logged in")
            self.inject_jquery()
            
          if matched == 'input[type=submit]':
            self.click_elements(elements)
  
            if DEBUG: print("Submit")
            self.inject_jquery()
            
        except AssertionError as e:
          raise e
        except Exception as e:
          pass
        
        delay(1)

      alerts = self.find_elements(['.alert'])
      if alerts and DEBUG:
        print(alerts)
                      
      SVPNCOOKIE=self.driver.get_cookie('SVPNCOOKIE')
      if SVPNCOOKIE: 
        if DEBUG: print('got svncookie')
        break
    
    if steps >= MAX_STEPS:
      if DEBUG: raise Exception('Failed to get cookie')
      pass

    if SVPNCOOKIE is None:
      delay(1) 
      SVPNCOOKIE=self.driver.get_cookie('SVPNCOOKIE')
      
    return SVPNCOOKIE.get('value',None)     
      
  def openvpn(self, cookie):

    def enqueue_output(out, queue):
      try:
        for line in iter(out.readline, b''):
          queue.put(line)
        out.close()
        delay(1)
      except Exception as e:
        pass

    # call openfortivpn
    if DEBUG: 
      print('Openfortivpn connecting')
    else:
      syslog.syslog(syslog.LOG_NOTICE,'Openfortivpn connecting')
    cmd = [
        '/usr/local/bin/openfortivpn',
        "-c", "/etc/openfortivpn/config",
        '--cookie=' + cookie,
      ]
    
    cmd += ['--trusted-cert=' + self.cert] if self.cert is not None else []
      
    p = subprocess.Popen(
      cmd,
      stdout=subprocess.PIPE, 
      stderr=subprocess.PIPE,
      close_fds=ON_POSIX)
    
    q=Queue()
    t=Thread(target=enqueue_output, args=(p.stdout, q))
    t.daemon = True
    t.start()

    #iptables_set()

    while p.poll() is None:
      try:
        line = q.get_nowait()
      except Empty:
        pass
      else:
        if DEBUG: print(line.decode('utf8'), end='')

      if not should_be_on():
        p.terminate()
        delay(3, randomize=False)
        p.kill()
        delay(3, randomize=False)    
        break

      delay(1)

    stdout, stderr = p.communicate()

    t.stop()

    if (p.returncode == 1):
      if '--trusted-cert' in stdout.decode('utf8'):
        self.cert = [ l.strip().split(' ') for l in stdout.decode('utf8').split() if '--trusted-cert' in l]
      else:
        print (stdout,stderr)
        return False
    return True

def iptables_set():
  try:
    p=subprocess.run('/usr/sbin/iptables -t nat -C POSTROUTING -d 172.16.0.0/12 -j MASQUERADE'.split(' '))
    if p.returncode != 0:
      if DEBUG: print('Creating iptables nat rule')
      p=subprocess.run('/usr/sbin/iptables -t nat -A POSTROUTING -d 172.16.0.0/12 -j MASQUERADE'.split(' '))
  except Exception:
    pass
  
def main():
  if DEBUG: print ('Number of arguments:', len(sys.argv), 'arguments.')
  if DEBUG: print ('Argument List:', str(sys.argv))

  iptables_set()

  if (len (sys.argv) == 1):
    sys.argv.append('yyyyy')
    sys.argv.append('xxxxx')

  config = configparser.ConfigParser()
  with open('/etc/openfortivpn/config') as conf:
    config.read_string('[DEFAULT]\n'+conf.read())
  config=config['DEFAULT']

  secret = configparser.ConfigParser()
  with open('/etc/openfortivpn/secret') as conf:
    secret.read_string('[DEFAULT]\n'+conf.read())
  secret=secret['DEFAULT']['secret']

  # cert = ssl.get_server_certificate((config['host'], config['port']))
  # cert = x509.load_pem_x509_certificate(cert.encode('utf-8')); 
  # algo = cert.signature_hash_algorithm.name.upper()
  # fingerprint = cert.fingerprint(getattr(hashes,algo)())

  if DEBUG: print ('Connecting to:',config['host'], config['port'], config['username'])

  cookie_is_valid = False if os.environ.get('SVPNCOOKIE',None) is None else True
  ts = VPN( config['host'], config['port'], config['username'], config['password'], secret, config['trusted-cert'], config['realm'])
  
  off_warn = False
  while True:
    try:
      if should_be_on():
        if off_warn: 
          if not DEBUG: 
            syslog.syslog(syslog.LOG_NOTICE,'In working hours, will connect')
          else: 
            print ('in working hours, connecting')
        if os.environ.get('SVPNCOOKIE',None) is None or not cookie_is_valid:
          syslog.syslog(syslog.LOG_NOTICE,'Getting new VPN cookie')
          ts.setup_method()
          SVPNCOOKIE = ts.login()
          ts.teardown_method()
          os.environ['SVPNCOOKIE']=SVPNCOOKIE
          if DEBUG: 
            print('VPN logged in. Cookie:', SVPNCOOKIE) 
          else:
            syslog.syslog(syslog.LOG_DEBUG,'Got a cookie')

        else:
          if not DEBUG: syslog.syslog(syslog.LOG_DEBUG,'Getting cookie from previous run')
          SVPNCOOKIE = os.environ['SVPNCOOKIE']
          if DEBUG: print('VPN logged in. Cookie:', SVPNCOOKIE)
        cookie_is_valid = ts.openvpn(SVPNCOOKIE)
        off_warn=False
      else:
        if not off_warn:
          if not DEBUG: 
            syslog.syslog(syslog.LOG_NOTICE,'Not in working hours, will not connect')
          else:
            print ('not in working hours')
        off_warn=True
    except Exception as e:
      pass
    delay(15)


if __name__ == '__main__':

  # if not DEBUG:
  #   syslog.syslog(syslog.LOG_INFO,'Starting openfortivpn-auth daemon')
  #   pidfile = "/run/openfortivpn-auth.pid"
  #   with daemon.DaemonContext(pidfile=pidfile):
  #     while True: delay(1)
  #     syslog.syslog(syslog.LOG_INFO,'Starting openfortivpn-auth daemon')
  #     main()
  # else:
    main()

  # exit(0) 
