import os
import re
from mitmproxy import http

# detection regex matches the same mime-types as the Intent filters for ExoAirPlayer:
#   https://github.com/warren-bank/Android-ExoPlayer-AirPlay-Receiver/blob/v3.4.5/android-studio-project/ExoPlayer-AirPlay-Receiver/src/main/AndroidManifest.xml#L119-L138

# format of output file
#   - is not valid JSON
#   - to produce valid JSON from content of file:
#     * trim from beginning: "\n,"
#     * prepend: "["
#     * append:  "]"

class DetectMediaFiles:
    def __init__(self):
        __dir__           = __file__.removesuffix('.py')
        self.output_path  = os.path.join(__dir__, 'output', 'media_files.json')
        self.report_path  = os.path.join(__dir__, 'input',  'media_files.html')
        self.detect_regex = re.compile("^(?:(?:audio|video)/.*|.*/(?:avi|mkv)|application/(?:dash\\+xml|mp4|ogg|vnd\\.(?:apple\\.mpegurl|ms\\-sstr\\+xml)|x\\-(?:extension\\-mp4|flac|matroska|mpegurl|ogg|rtmp|rtsp)|(?:3gpp|mpeg|vnd\\.3gp).*))$", re.IGNORECASE)

    def response(self, flow):
        if ('content-type' in flow.response.headers) and self.detect_regex.match(flow.response.headers['content-type']):
            media_url   = flow.request.pretty_url
            media_type  = flow.response.headers['content-type']
            referer_url = flow.request.headers['referer'] if ('referer' in flow.request.headers) else ''

            file = open(self.output_path, mode='a+t', encoding='utf-8')
            file.write("\n," + f'{{"media_url":"{media_url}","media_type":"{media_type}","referer_url":"{referer_url}"}}')
            file.close()

    def request(self, flow):
        if flow.request.pretty_url == 'https://example.com/detect_media_files.json':
            try:
                file = open(self.output_path, mode='rt', encoding='utf-8')
                json_text = file.read()
                file.close()
            except IOError:
                json_text = None

            if json_text:
                json_text = '[' + json_text.removeprefix("\n,") + ']'
            else:
                json_text = '[]'

            flow.response = http.Response.make(
                200,
                bytes(json_text, 'utf-8'),
                {'Content-Type': 'application/json'}
            )

        if flow.request.pretty_url == 'https://example.com/detect_media_files.html':
            try:
                file = open(self.report_path, mode='rb')
                html_bytes = file.read()
                file.close()
            except IOError:
                html_bytes = None

            if html_bytes:
                flow.response = http.Response.make(
                    200,
                    html_bytes,
                    {'Content-Type': 'text/html'}
                )
            else:
                flow.response = http.Response.make(404, b'File not found')

addons = [DetectMediaFiles()]
