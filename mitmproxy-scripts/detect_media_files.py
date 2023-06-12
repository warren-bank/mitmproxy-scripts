import os
import re

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
        self.detect_regex = re.compile("^(?:(?:audio|video)/.*|.*/(?:avi|mkv)|application/(?:dash\\+xml|mp4|ogg|vnd\\.(?:apple\\.mpegurl|ms\\-sstr\\+xml)|x\\-(?:extension\\-mp4|flac|matroska|mpegurl|ogg|rtmp|rtsp)|(?:3gpp|mpeg|vnd\\.3gp).*))$", re.IGNORECASE)

    def response(self, flow):
        if ('content-type' in flow.response.headers) and self.detect_regex.match(flow.response.headers['content-type']):
            media_url   = flow.request.pretty_url
            media_type  = flow.response.headers['content-type']
            referer_url = flow.request.headers['referer'] if ('referer' in flow.request.headers) else ''

            file = open(self.output_path, 'a+')
            file.write("\n," + f'{{"media_url":"{media_url}","media_type":"{media_type}","referer_url":"{referer_url}"}}')
            file.close()

addons = [DetectMediaFiles()]
