from androguard import misc
from androguard import session
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes import apk
import hashlib
from db import *
import sys

NS_ANDROID_URI = "http://schemas.android.com/apk/res/android"
NS_ANDROID = '{http://schemas.android.com/apk/res/android}'

def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()






app = apk_db(sys.argv[2])
app_sha256 = sha256sum(sys.argv[1])

print("Analyzing apk with SHA256:{}".format(app_sha256))


# apk_r, dex, analysis = AnalyzeAPK(sys.argv[1])
apk_r = apk.APK(sys.argv[1])
print("Finished Analyzing apk....")


app_attributes = (app_sha256,apk_r.get_app_name(),apk_r.get_package(),apk_r.get_androidversion_code(),apk_r.get_androidversion_name(),
apk_r.get_min_sdk_version(),apk_r.get_target_sdk_version(),apk_r.get_max_sdk_version(),'|'.join(apk_r.get_permissions()),'|'.join(apk_r.get_libraries()))

app_permissions = apk_r.get_details_permissions()



app.update_application(app_attributes)



for permission in app_permissions:
    entry = (app_sha256,permission,)+tuple(app_permissions[permission])
    app.update_permissions(entry)


manifest = apk_r.get_android_manifest_axml().get_xml_obj()
application = manifest.findall("application")[0]


if application.get(NS_ANDROID+"debuggable") == 'true':
    print("Debuggable...")

if application.get(NS_ANDROID+"allowBackup") == 'true':
    print("allowBackup...")

for activity in application.findall("activity"):
    activityName = activity.get(NS_ANDROID+"name")
    print(activityName)
    if activity.get(NS_ANDROID+"exported") == 'true':
        print( activityName+ ' ' +' is exported')
