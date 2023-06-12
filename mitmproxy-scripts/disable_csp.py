class DisableCsp:
    def __init__(self):
        self.csp_response_headers = ["content-security-policy", "content-security-policy-report-only", "x-content-security-policy", "x-webkit-csp", "x-xss-protection"]

    def response(self, flow):
        for header in self.csp_response_headers:
            if header in flow.response.headers:
                del flow.response.headers[header]

addons = [DisableCsp()]
