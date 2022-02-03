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



def fill_activities(application,sha256):

    for activity in application.findall("activity"):
        activityName = activity.get(NS_ANDROID+"name")
        enabled = activity.get(NS_ANDROID+"enabled")
        exported = activity.get(NS_ANDROID+"exported")
        autoRemoveFromRecents = activity.get(NS_ANDROID+"autoRemoveFromRecents")
        excludeFromRecents = activity.get(NS_ANDROID+"excludeFromRecents")
        noHistory = activity.get(NS_ANDROID+"noHistory")
        permission = activity.get(NS_ANDROID+"permission")
        activity_attribs = (sha256, activityName, enabled, exported,autoRemoveFromRecents, excludeFromRecents,noHistory,permission)
        app.update_activities(activity_attribs)

def fill_services(application,sha256):

    for service in application.findall("service"):
        servicename = service.get(NS_ANDROID+"name")
        enabled = service.get(NS_ANDROID+"enabled")
        exported = service.get(NS_ANDROID+"exported")
        foregroundServiceType = service.get(NS_ANDROID+"foregroundServiceType")
        permission = service.get(NS_ANDROID+"permission")
        process = service.get(NS_ANDROID+"process")
        service_attribs = (sha256, servicename, enabled, exported,foregroundServiceType, permission,process)
        app.update_services(service_attribs)


      






app = apk_db(sys.argv[2])
app_sha256 = sha256sum(sys.argv[1])

print("Analyzing apk with SHA256:{}".format(app_sha256))


# apk_r, dex, analysis = AnalyzeAPK(sys.argv[1])
apk_r = apk.APK(sys.argv[1])

manifest = apk_r.get_android_manifest_axml().get_xml_obj()
application = manifest.findall("application")[0]

print("Finished Analyzing apk....")


app_attributes = (app_sha256,apk_r.get_app_name(),apk_r.get_package(),apk_r.get_androidversion_code(),apk_r.get_androidversion_name(),
apk_r.get_min_sdk_version(),apk_r.get_target_sdk_version(),apk_r.get_max_sdk_version(),
'|'.join(apk_r.get_permissions()),'|'.join(apk_r.get_libraries())) + (application.get(NS_ANDROID+"debuggable"), application.get(NS_ANDROID+"allowBackup"))

app_permissions = apk_r.get_details_permissions()


app.update_application(app_attributes)


for permission in app_permissions:
    entry = (app_sha256,permission,)+tuple(app_permissions[permission])
    app.update_permissions(entry)



fill_activities(application,app_sha256)

fill_services(application,app_sha256)



   



  