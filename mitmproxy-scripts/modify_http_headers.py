import asyncio, json, os, re
from glob import glob

# --------------------------------------
# only one rule set is active at runtime.
#
# each rule set supports the use of a glob pattern,
# to optionally include multiple JSON files.
#
# all matching JSON files must obey the naming convention:
#   request  rules end with the filename suffix: '.req_rules.json'
#   response rules end with the filename suffix: '.res_rules.json'
# --------------------------------------
rule_sets = ["*", "00-demo"]

current_rule_set_index = 1

class ModifyHttpHeaders:
    def __init__(self):
        self.req_rules = None
        self.res_rules = None
        asyncio.create_task(self.load_rules())

    async def load_rules(self):
        # JSON schema is described here:
        #   https://github.com/warren-bank/moz-rewrite/tree/json/master#data-structure

        __dir__ = __file__[:-3]  # removesuffix('.py')
        __req__ = os.path.join(__dir__, 'input', rule_sets[current_rule_set_index] + '.req_rules.json')
        __res__ = os.path.join(__dir__, 'input', rule_sets[current_rule_set_index] + '.res_rules.json')

        self.req_rules = self.read_rules(__req__)
        self.res_rules = self.read_rules(__res__)

    def read_rules(self, __glob__):
        try:
            filenames = glob(__glob__)
        except:
            filenames = []

        all_rules = []
        for fpath in filenames:
            try:
                file  = open(fpath, mode='rt', encoding='utf-8')
                rules = json.load(file)
                file.close()

                rules = self.preprocess_rules(rules)
                if rules:
                    all_rules.extend(rules)
            except:
                pass

        return all_rules

    def preprocess_rules(self, rules):
        if not rules or not isinstance(rules, list):
            return None

        processed_rules = []
        for rule in rules:
            if isinstance(rule, dict) and ('url' in rule) and ('headers' in rule) and rule['url'] and rule['headers']:
                rule['url'] = re.compile(rule['url'], re.IGNORECASE)
                processed_rules.append(rule)

        return processed_rules

    def request(self, flow):
        self.apply_rules(flow.request.headers, self.req_rules, flow.request.pretty_url)

    def response(self, flow):
        self.apply_rules(flow.response.headers, self.res_rules, flow.request.pretty_url)

    def apply_rules(self, headers, rules, url):
        if not rules:
            return

        for rule in rules:
            if rule['url'].match(url):
                for header_name in rule['headers']:
                    header_name_lc = header_name.lower()
                    if rule['headers'][header_name]:
                        headers[header_name_lc] = rule['headers'][header_name]
                    else:
                        headers.pop(header_name_lc, None)
                if ('stop' in rule) and rule['stop']:
                    break

addons = [ModifyHttpHeaders()]
