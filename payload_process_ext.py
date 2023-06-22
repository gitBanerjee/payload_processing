from burp import IBurpExtender, IIntruderPayloadProcessor

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor):

    def __init__(self):
        self.collaborator_id = '5bhmispoextucclxjo4asm8ct3zunj.burpcollaborator.net'
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Payload Processor")
        callbacks.registerIntruderPayloadProcessor(self)
        
    def getProcessorName(self):
        return "Payload Processor"
    
    def processPayload(self, currentPayload, originalPayload, baseValue):
        _currentPayload = self._helpers.bytesToString(currentPayload)
        finalPayload = _currentPayload
        if '<BURP_COLLABORATOR_HOST>' in _currentPayload:
            finalPayload = finalPayload.replace('<BURP_COLLABORATOR_HOST>', self.collaborator_id)
        if '<SERVER>' in _currentPayload:
            finalPayload = finalPayload.replace('<SERVER>', 'NS')
        if '<USERNAME>' in _currentPayload:
            finalPayload = finalPayload.replace('<USERNAME>', 'sourav')
        if '<BURP_COLLABORATOR_HOST_HALF_LINK>' in _currentPayload:
            finalPayload = finalPayload.replace('<BURP_COLLABORATOR_HOST_HALF_LINK>', self.collaborator_id.split('burp')[0] + 'burp')
        if '<BURP_COLLABORATOR_HOST_ANOTHER_HALF_LINK>' in _currentPayload:
            finalPayload = finalPayload.replace('<BURP_COLLABORATOR_HOST_ANOTHER_HALF_LINK>', self.collaborator_id.split('burp')[1])
        if '<BURP_COLLABORATOR_EMAIL>' in _currentPayload:
            finalPayload = finalPayload.replace('<BURP_COLLABORATOR_EMAIL>', 'sourav@' + self.collaborator_id)
        return self._helpers.stringToBytes(finalPayload)
    
    def getProcessorPayload(self, currentPayload, originalPayload, baseValue):
        print(currentPayload)
        return currentPayload
