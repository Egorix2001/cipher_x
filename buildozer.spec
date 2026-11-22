[app]
title = Cipher-X
package.name = cipherx
package.domain = org.darkmoulder
source.dir = .
source.include_exts = py
version = 2.1
requirements = python3,kivy==2.3.0,pycryptodome,pyjnius,android
orientation = portrait
fullscreen = 0
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,MANAGE_EXTERNAL_STORAGE
android.api = 34
android.minapi = 24
android.archs = arm64-v8a
android.accept_sdk_license = True
android.allow_backup = False

[buildozer]
log_level = 2
warn_on_root = 0
