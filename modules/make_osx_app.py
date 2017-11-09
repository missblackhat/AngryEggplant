#!/usr/bin/python
# -*- coding: utf-8 -*-
import os

def main(filename, icon=None, version="1.0.0"):
    """Create a Mac OS X .app application-bundle with a Python script or a Macho compiled-binary"""
    
    if not len(filename):
        return 'Error: must specify a target file'
    else:
        filename = os.path.normpath(filename)
    if not os.path.isfile(filename):
        return 'Error: target file does not exist'
    if not filename in os.listdir('.'):
        os.chdir(os.path.dirname(filename))
    try:
        bundleName      = os.path.splitext(os.path.basename(filename))[0]
        bundleVersion   = bundleName + " " + version
        bundleIdentify  = "com." + bundleName
        appPath         = os.path.join(os.getcwd(), bundleName + '.app')
        basePath        = os.path.join(appPath, 'Contents')
        distPath 	= os.path.join(basePath, 'MacOS')
        rsrcPath        = os.path.join(basePath, 'Resources')
        pkgFile         = os.path.join(basePath, 'PkgInfo')
        plistFile       = os.path.join(rsrcPath, 'Info.plist')
        executable      = os.path.join(distPath, filename)
        iconPath        = os.path.join(rsrcPath, icon) if icon else None
    except Exception as ze:
        print "Define variable returned error: {}".format(str(ze))


    os.makedirs(distPath)
    os.mkdir(rsrcPath)

    with file(pkgFile, "w") as fp:
        fp.write("APPL????")

    if icon:
        if not iconPath.endswith('.icns'):
            return "Error: Mac OS X application bundle icon must be a '.icns' image file"
        with file(iconPath, "w") as iw:
            with open(icon, 'r') as ir:
                iw.write(ir.read())
    else:
        exFile = os.path.basename(filename)
        with file(distPath + os.sep + exFile, 'w') as fp:
            with open(filename, 'r') as content:
                fp.write(content.read())

    infoPlist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleDevelopmentRegion</key>
<string>English</string>
<key>CFBundleExecutable</key>
<string>%s</string>
<key>CFBundleGetInfoString</key>
<string>%s</string>
<key>CFBundleIconFile</key>
<string>%s</string>
<key>CFBundleIdentifier</key>
<string>%s</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundleName</key>
<string>%s</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleShortVersionString</key>
<string>%s</string>
<key>CFBundleSignature</key>
<string>????</string>
<key>CFBundleVersion</key>
<string>%s</string>
<key>NSAppleScriptEnabled</key>
<string>YES</string>
<key>NSMainNibFile</key>
<string>MainMenu</string>
<key>NSPrincipalClass</key>
<string>NSApplication</string>
</dict>
</plist>""" % (filename, bundleVersion, icon, bundleIdentify, bundleName, bundleVersion, version)

    with file(plistFile, "w") as fw:
        fw.write(infoPlist)

    os.chmod(executable, 0755)
    return appPath

