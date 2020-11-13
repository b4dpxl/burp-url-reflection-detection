## URL Reflection Detection

BurpSuite extension which adds a new, random querystring to all requests, and looks for this reflected in the response. I found that Burp wasn't always picking up URLs and querystrings being reflected, so this attempts to resolve this by adding an explicit marker.

The new parameter takes the format `?__canary=abcdefgh`, and an issue will be raised if it's matched in the response header and/or body. A comment will also be added to the requests to indicate it's been added, as it won't show up automatically.

Other extensions like Reflected Parameters will also pick up the reflection.

This is disabled by default, as some apps don't like it. Use the new menu to enable it, and limit it to only in-scope requests (this is enabled by default).