# For use in a windows env

from ctypes import byref, create_string_buffer, c_ulong, windll
from io import StringIO 

import os 
import pythoncom
import pyWinhook as pyHook #pyWinHook will not build - last update was 2020. repo can be found here. https://github.com/Tungsteno74/pyWinhook


