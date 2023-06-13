# ------------------------------------------------
# An mitmproxy adblock script!
# (Required python modules: re2 and adblockparser)
#
# (c) 2015-2019 epitron
#
# ------------------------------------------------
# https://github.com/epitron/mitm-adblock
# https://github.com/epitron/mitm-adblock/blob/master/adblock.py
#
# based on:
#   version: 0.1.0
#   date:    2021-03-09
#   commit:  1de914dabc11b50183acdf9bbf7e4aaced6ff91b
#   license: WTFPL
#            "DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE"
#            https://github.com/epitron/mitm-adblock/blob/1de914dabc11b50183acdf9bbf7e4aaced6ff91b/LICENSE.txt
# ------------------------------------------------

import os, re, sys
import urllib.request
from glob import glob
from mitmproxy import http

__dir__ = __file__.removesuffix('.py')
sys.path.append(os.path.join(__dir__, 'libs'))

from adblockparser import AdblockRules

class AdBlock:

    def __init__(self):
        self.IMAGE_MATCHER      = re.compile(r"\.(png|jpe?g|gif)$")
        self.SCRIPT_MATCHER     = re.compile(r"\.(js)$")
        self.STYLESHEET_MATCHER = re.compile(r"\.(css)$")

        __dir__ = __file__.removesuffix('.py')
        __dir__ = os.path.join(__dir__, 'output', 'blocklists')

        default_blocklist_urls = [
            'https://easylist-downloads.adblockplus.org/easylist.txt',
            'https://easylist-downloads.adblockplus.org/easyprivacy.txt',
            'https://easylist-downloads.adblockplus.org/fanboy-annoyance.txt',
            'https://easylist-downloads.adblockplus.org/fanboy-social.txt'
        ]

        for index, url in enumerate(default_blocklist_urls):
            fpath = os.path.join(__dir__, str(index + 1) + '.txt')

            try:
                os.remove(fpath)
            except:
                pass

            try:
                urllib.request.urlretrieve(url, fpath)
            except:
                pass

        try:
            blocklists = glob(os.path.join(__dir__, '*'))
        except:
            blocklists = []

        if len(blocklists) > 0:
          self.rules = self.load_rules(blocklists)
        else:
          self.rules = None

    def load_rules(self, blocklists=None):
        rules = AdblockRules(
            self.combined(blocklists),
            use_re2=False,
            max_mem=32*1024*1024
            # supported_options=['script', 'domain', 'image', 'stylesheet', 'object']
        )
        return rules

    # Open and combine many files into a single generator,
    # which returns all of their lines.
    # (Like running "cat" on a bunch of files.)
    def combined(self, filenames):
      for filename in filenames:
        with open(filename) as file:
          for line in file:
            yield line

    def request(self, flow):
        req     = flow.request
        options = {'domain': req.host}

        if self.IMAGE_MATCHER.search(req.path):
            options["image"] = True
        elif self.SCRIPT_MATCHER.search(req.path):
            options["script"] = True
        elif self.STYLESHEET_MATCHER.search(req.path):
            options["stylesheet"] = True

        if self.rules and self.rules.should_block(req.url, options):
            flow.response = http.Response.make(
                200,
                b"BLOCKED.",
                {"Content-Type": "text/html"}
            )

addons = [AdBlock()]
