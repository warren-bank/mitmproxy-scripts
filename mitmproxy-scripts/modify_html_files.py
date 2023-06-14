import asyncio, json, os, re
from glob import glob

class ModifyHtmlFiles:
    def __init__(self):
        __dir__ = __file__.removesuffix('.py')
        __dir__ = os.path.join(__dir__, 'input')

        self.rules = None
        asyncio.create_task(self.load_rules(__dir__))

    async def load_rules(self, __dir__):
        try:
            filenames = glob(os.path.join(__dir__, '*.json'))
        except:
            filenames = []

        rules = []
        for fpath in filenames:
            try:
                file = open(fpath, mode='rt', encoding='utf-8')
                rule = json.load(file)
                file.close()

                if isinstance(rule, dict) and (('regex_url' in rule) and rule['regex_url']) and ((('regex_insert_before' in rule) and rule['regex_insert_before']) or (('regex_insert_after' in rule) and rule['regex_insert_after']) or (('regex_insert_between' in rule) and rule['regex_insert_between'])):
                    rule['filename']  = fpath.removesuffix('.json') + '.txt'
                    rule['regex_url'] = re.compile(rule['regex_url'], re.IGNORECASE)

                    if ('regex_insert_before' in rule) and rule['regex_insert_before']:
                        rule['regex_insert_before'] = re.compile(rule['regex_insert_before'], re.IGNORECASE)
                    if ('regex_insert_after' in rule) and rule['regex_insert_after']:
                        rule['regex_insert_after'] = re.compile(rule['regex_insert_after'], re.IGNORECASE)
                    if ('regex_insert_between' in rule) and rule['regex_insert_between']:
                        rule['regex_insert_between'] = re.compile(rule['regex_insert_between'], re.IGNORECASE)

                    rules.append(rule)
            except IOError:
                pass

        self.rules = rules

    def response(self, flow):
        if not self.rules:
            return

        content_type = flow.response.headers.get("content-type", "")
        if (not content_type) or (not "text/html" in content_type):
            return

        matches = []
        for rule in self.rules:
            if rule['regex_url'].match(flow.request.pretty_url):
                matches.append(rule)

        if not matches:
            return

        # IMPORTANT: delete these, otherwise it may upgrade the connection to QUIC
        # You may also need to block the QUIC protocol, as it seems like chrome still tries to use QUIC
        flow.response.headers.pop("alt-svc", None)
        flow.response.headers["alt-svc"] = "clear"

        # Remove error reporting
        flow.response.headers.pop("report-to", None)
        flow.response.headers.pop("nel", None)

        # Disable caching
        flow.response.headers["cache-control"] = "no-store"
        flow.response.headers["expires"] = "0"

        if not flow.response.content:
            # NOTE: even if cached (http 304), the above headers should invalidate it for the next request
            return

        html = str(flow.response.content, 'utf-8')

        for rule in matches:
            file = open(rule['filename'], mode='rt', encoding='utf-8')
            text = file.read()
            file.close()

            if ('regex_insert_before' in rule) and rule['regex_insert_before']:
                insertion_point = rule['regex_insert_before'].search(html)

                if insertion_point:
                    index = insertion_point.span()[0]
                    html = html[:index] + text + html[index:]
                    continue

            if ('regex_insert_after' in rule) and rule['regex_insert_after']:
                insertion_point = rule['regex_insert_after'].search(html)

                if insertion_point:
                    index = insertion_point.span()[1]
                    html = html[:index] + text + html[index:]
                    continue

            if ('regex_insert_between' in rule) and rule['regex_insert_between']:
                insertion_point = rule['regex_insert_between'].search(html)

                if insertion_point:
                    try:
                        indexs = insertion_point.span()
                        groups = [insertion_point.group(1), insertion_point.group(2)]
                        html = html[:indexs[0]] + groups[0] + text + groups[1] + html[indexs[1]:]
                        continue
                    except:
                        pass

        flow.response.text = html

addons = [ModifyHtmlFiles()]
