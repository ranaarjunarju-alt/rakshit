from androguard.core.apk import APK
a=APK("/home/user/rakshit/TopFollow_v845-Beta (1).apk")
print(a.get_android_manifest_axml().get_xml().decode('utf-8','replace'))
