import json
import os
import re

rule_sets = ["00-demo"]

current_rule_set_index = 0

class ModifyHttpHeaders:
    def __init__(self):
        __dir__ = __file__.removesuffix('.py')
        __req__ = os.path.join(__dir__, 'input', rule_sets[current_rule_set_index] + '.req_rules.json')
        __res__ = os.path.join(__dir__, 'input', rule_sets[current_rule_set_index] + '.res_rules.json')

        # JSON schema is described here:
        #   https://github.com/warren-bank/moz-rewrite/tree/json/master#data-structure

        try:
            f = open(__req__, mode='rt', encoding='utf-8')
            self.req_rules = json.load(f)
            f.close()

            if not isinstance(self.req_rules, list):
                raise IOError('not an array')
        except IOError:
            self.req_rules = []

        try:
            f = open(__res__, mode='rt', encoding='utf-8')
            self.res_rules = json.load(f)
            f.close()

            if not isinstance(self.res_rules, list):
                raise IOError('not an array')
        except IOError:
            self.res_rules = []

        for index, rule in reversed(list(enumerate(self.req_rules))):
            if isinstance(rule, dict) and ('url' in rule) and ('headers' in rule) and rule['url'] and rule['headers']:
                rule['url'] = re.compile(rule['url'], re.IGNORECASE)
            else:
                del self.req_rules[index]

        for index, rule in reversed(list(enumerate(self.res_rules))):
            if isinstance(rule, dict) and ('url' in rule) and ('headers' in rule) and rule['url'] and rule['headers']:
                rule['url'] = re.compile(rule['url'], re.IGNORECASE)
            else:
                del self.res_rules[index]

    def request(self, flow):
        for rule in self.req_rules:
            if rule['url'].match(flow.request.pretty_url):
                for header_name in rule['headers']:
                    if rule['headers'][header_name]:
                        flow.request.headers[header_name] = rule['headers'][header_name]
                    else:
                        del flow.request.headers[header_name]
                if ('stop' in rule) and rule['stop']:
                    break

    def response(self, flow):
        for rule in self.res_rules:
            if rule['url'].match(flow.request.pretty_url):
                for header_name in rule['headers']:
                    if rule['headers'][header_name]:
                        flow.response.headers[header_name] = rule['headers'][header_name]
                    else:
                        del flow.response.headers[header_name]
                if ('stop' in rule) and rule['stop']:
                    break

addons = [ModifyHttpHeaders()]
