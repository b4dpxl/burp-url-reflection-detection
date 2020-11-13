## URL Reflection Detection

BurpSuite extension which adds a new, random querystring to all requests (in-scope only!), and looks for this reflected in the response. I found that Burp wasn't always picking up URLs and querystrings being reflected, so this attempts to resolve this by adding an explicit marker.

The new parameter takes the format `?__canary=abcdefgh`, and an issue will be raised if it's matched in the response header and/or body. A comment will also be added to the requests to indicate it's been added, as it won't show up automatically.

Other extensions like Reflected Parameters will also pick up the reflection.

Some apps don't like it, so you may have to selectively enable/disable the extension. Alternatively it could be converted to a Session Handling action fairly easily, but that will need to be explicitly enabled for each project :shrug:
