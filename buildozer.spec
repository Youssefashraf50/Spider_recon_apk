[app]
title = SpiderRecon
package.name = spiderrecon
package.domain = org.youssefashraf
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,kivy,urllib3,ssl
orientation = portrait
osx.python_version = 3
osx.kivy_version = 2.1.0
fullscreen = 0
android.api = 31
android.minapi = 21
android.ndk = 23b
android.sdk = 31
android.gradle_dependencies = ''
android.add_src = 
android.permissions = INTERNET,ACCESS_NETWORK_STATE
android.manifest.intent_filters = 

[buildozer]
log_level = 1
warn_on_root = 1

[app:source]
p4a.source_dir = 

[app:buildozer:ci]
p4a.local_recipes =
