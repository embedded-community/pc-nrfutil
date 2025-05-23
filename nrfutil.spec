# -*- mode: python -*-

import importlib
import os
import sys

block_cipher = None

module = importlib.import_module("pc_ble_driver_py")
mod_dir = os.path.dirname(module.__file__)
shlib_dir = os.path.join(os.path.abspath(mod_dir), 'lib')
hex_dir = os.path.join(os.path.abspath(mod_dir), 'hex')

datas = [(shlib_dir, 'lib'), (hex_dir, 'pc_ble_driver_py/hex')]

nrfutil_path = os.path.dirname(os.path.abspath(SPEC))
datas.append((os.path.join(nrfutil_path, "libusb", "x64", "libusb-1.0.dylib"), os.path.join("libusb", "x64")))
datas.append((os.path.join(nrfutil_path, "libusb", "x86", "libusb-1.0.dll"), os.path.join("libusb", "x86")))
datas.append((os.path.join(nrfutil_path, "libusb", "x64", "libusb-1.0.dll"), os.path.join("libusb", "x64")))
              
a = Analysis(['nordicsemi/__main__.py'],
             binaries=None,
             datas=datas,
             hiddenimports=['usb1'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

pyz = PYZ(a.pure, a.zipped_data,
          cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='nrfutil',
          debug=False,
          strip=False,
          upx=True,
          console=True)
