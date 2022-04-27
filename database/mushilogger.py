import logging 
from logging import getLogger, FileHandler, Formatter
import subprocess

class MushiLogger():
  logger = getLogger("mushikago logger")
  logger.setLevel(logging.DEBUG)
  
  handler = FileHandler(filename="mushikago.log")
  handler.setFormatter(Formatter("%(asctime)s %(levelname)8s %(message)s"))
  
  logger.addHandler(handler)

    
  def __init__(self):
    #print("init MushiLogger")
    pass


  def writelog(self, arg, mode):
    if mode == "debug":
      self.logger.debug(arg)
    elif mode == "info":
      self.logger.info(arg)
    elif mode == "warn":
      self.logger.warning(arg)
    elif mode == "error":
      self.logger.error(arg)
    
    #logger.info(result.stdout.decode('utf-8'))
