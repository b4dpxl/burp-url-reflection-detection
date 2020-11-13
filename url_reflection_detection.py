from array import array
from burp import IBurpExtender, IHttpListener, IScanIssue, IExtensionStateListener

# IExtensionStateListener is to detect unloading

from javax import swing
from java.awt import Frame

import random
import re
import string
import sys
import traceback

from java.net import URL


NAME = "URL Reflection Detection"


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception:
            sys.stderr.write('\n\n*** PYTHON EXCEPTION\n')
            traceback.print_exc(file=sys.stderr)
            raise
    return wrapper


class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener):

    _callbacks = None
    _helpers = None

    _field = "__canary="

    def __init__(self):
        self._field
        self._parameter = self._field + ''.join(random.choice(string.ascii_lowercase) for c in range(8))
        print("Using random querystring parameter {}".format(self._parameter))

        burp_frame = None
        for frame in Frame.getFrames():
            if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
                burp_frame = frame

        self._menu = swing.JMenu("Reflect/Detect")
        # TODO make it remember the settings
        self._enabled_menu = swing.JCheckBoxMenuItem("Enabled", False)
        self._menu.add(self._enabled_menu)
        self._scope_menu = swing.JCheckBoxMenuItem("In scope only", True)
        self._menu.add(self._scope_menu)
        bar = burp_frame.getJMenuBar()
        bar.add(self._menu, bar.getMenuCount())
        bar.repaint()

    def extensionUnloaded(self):
        print("unloading " + NAME)
        bar = self._menu.getParent()
        bar.remove(self._menu)
        bar.repaint()

    def registerExtenderCallbacks(self, callbacks):
        # for error handling
        sys.stdout = callbacks.getStdout()  
        sys.stderr = callbacks.getStderr()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(NAME)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerHttpListener(self)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName() and existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        return 0

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if not self._enabled_menu.isSelected():
            return

        requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        if self._scope_menu.isSelected() and not self._callbacks.isInScope(requestInfo.getUrl()):
            return

        if messageIsRequest:

            body = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            bodyString = self._helpers.bytesToString(body).encode('ascii', 'ignore')
            headers = requestInfo.getHeaders()
            http_method, path, _x, querystring, http_version = re.findall(r"""^(?P<method>\w+) (?P<URL>[^ \?]+)(\?(?P<QS>[^ ]+))? (?P<http>.*)$""", headers[0])[0]
            
            if querystring and self._field in querystring:
                # don't re-add the header
                # print("already exists in {}".format(querystring))
                return

            if querystring:
                URI = '{}?{}&{}'.format(path, querystring, self._parameter)
                # URI = path + '?' + querystring + '&' + self._parameter
            else:
                URI = '{}?{}'.format(path, self._parameter)
                # URI = path + '?' + self._parameter

            headers[0] = "{} {} {}".format(http_method, URI, http_version)
            messageInfo.setRequest(self._helpers.buildHttpMessage(headers, body))
            messageInfo.setComment("Added random querystring parameter: {}".format(self._parameter))

        else:
            responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            resp = self._helpers.analyzeResponse(messageInfo.getResponse())
            offset = responseInfo.getBodyOffset()
            rawString = self._helpers.bytesToString(messageInfo.getResponse()).encode('ascii', 'ignore')
            # body = messageInfo.getResponse()[offset:]
            # bodyString = self._helpers.bytesToString(body).encode('ascii', 'ignore')

            if self._parameter in rawString:
                markers = []
                count = 0
                in_header = False
                in_body = False
                for m in re.finditer(self._parameter, rawString):
                    markers.append(array('i', [m.start(), m.end()]))
                    if m.start() < offset:
                        in_header = True
                    else:
                        in_body = True
                    count += 1

                s = requestInfo.getHeaders()[0].index(self._parameter)
                messages = [self._callbacks.applyMarkers(
                    messageInfo, 
                    [array('i', [s, s + len(self._parameter)])], 
                    markers
                )]

                url = URL(requestInfo.getUrl().getProtocol(), requestInfo.getUrl().getHost(), requestInfo.getUrl().getPort(), requestInfo.getUrl().getPath());

                if in_header:
                    location = "header"

                if in_body:
                    if in_header:
                        location += " and body"
                    else:
                        location = "body"

                issue = ReflectionScanIssue(
                    messageInfo.getHttpService(),
                    url,
                    messages,
                    """The inserted querystring parameter was reflected {} time(s) in the HTTP response {}.""".format(count, location),
                    severity="Low" if in_body else "Information"

                )
                is_new_issue = True
                for existingIssue in self._callbacks.getScanIssues(str(messageInfo.getHttpService())):
                    if (
                        existingIssue.getUrl() == issue.getUrl() and 
                        existingIssue.getIssueName() == issue.getIssueName() and
                        existingIssue.getIssueDetail() == issue.getIssueDetail()
                    ):
                        is_new_issue = False
                
                if is_new_issue:
                    self._callbacks.addScanIssue(issue)

    # def getActionName(self):
    #     return "Add a semi-random querystring to requests"

    # def performAction(self, currentRequest, macroItems):  
    #     requestInfo = self._helpers.analyzeRequest(currentRequest)
    #     body = self._helpers.bytesToString(currentRequest.getRequest()[requestInfo.getBodyOffset():]).encode('ascii', 'ignore')

    #     headers = requestInfo.getHeaders()
    #     http_method, path, _x, querystring, http_version = re.findall(r"""^(?P<method>\w+) (?P<URL>[^ \?]+)(\?(?P<QS>[^ ]+))? (?P<http>.*)$""", headers[0])[0]
        
    #     URI = path
    #     if querystring:
    #         URI += '?' + querystring + '&'
    #     else:
    #         URI += '?'
    #     URI += '_canary_=' + self._string

    #     headers[0] = "{} {} {}".format(http_method, URI, http_version)
    #     edited_req = '\r\n'.join(headers) + '\r\n\r\n' + body
    #     currentRequest.setRequest(edited_req)
    #     currentRequest.setComment("Added random querystring: " + self._string)
        

class ReflectionScanIssue (IScanIssue):

    def __init__(self, httpService, url, httpMessages, detail, severity="Low", confidence="Firm"):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "URL reflection detection"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def setIssueDetail(self, detail):
        self._detail = detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService