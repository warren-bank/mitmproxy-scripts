# ------------------------------------------------
# https://github.com/scrapinghub/adblockparser
# https://github.com/scrapinghub/adblockparser/tree/master/adblockparser
#
# based on:
#   version: 0.7
#   date:    2016-10-17
#   commit:  4089612d65018d38dbb88dd7f697bcb07814014d
#   license: MIT
#            https://github.com/scrapinghub/adblockparser/blob/4089612d65018d38dbb88dd7f697bcb07814014d/LICENSE.txt
# ------------------------------------------------

import re
from collections import defaultdict


class AdblockParsingError(ValueError):
    pass


class AdblockRule(object):
    r"""
    AdBlock Plus rule.

    Check these links for the format details:

    * https://adblockplus.org/en/filter-cheatsheet
    * https://adblockplus.org/en/filters

    Instantiate AdblockRule with a rule line:

    >>> from adblockparser import AdblockRule
    >>> rule = AdblockRule("@@||mydomain.no/artikler/$~third-party")

    Parsed data is available as rule attributes:

    >>> rule.is_comment
    False
    >>> rule.is_exception
    True
    >>> rule.is_html_rule
    False
    >>> rule.options
    {'third-party': False}
    >>> print(rule.regex)
    ^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?mydomain\.no/artikler/

    To check if rule applies to an URL, use ``match_url`` method::

    >>> rule = AdblockRule("swf|")
    >>> rule.match_url("http://example.com/annoyingflash.swf")
    True
    >>> rule.match_url("http://example.com/swf/index.html")
    False

    Rules involving CSS selectors are detected but not supported well
    (``match_url`` doesn't work for them):

    >>> AdblockRule("domain.co.uk,domain2.com#@#.ad_description").is_html_rule
    True
    >>> AdblockRule("##.spot-ad").is_html_rule
    True
    """

    BINARY_OPTIONS = [
        "script",
        "image",
        "stylesheet",
        "object",
        "xmlhttprequest",
        "object-subrequest",
        "subdocument",
        "document",
        "elemhide",
        "other",
        "background",
        "xbl",
        "ping",
        "dtd",
        "media",
        "third-party",
        "match-case",
        "collapse",
        "donottrack",
        "websocket",
    ]
    OPTIONS_SPLIT_PAT = ',(?=~?(?:%s))' % ('|'.join(BINARY_OPTIONS + ["domain"]))
    OPTIONS_SPLIT_RE = re.compile(OPTIONS_SPLIT_PAT)

    __slots__ = ['raw_rule_text', 'is_comment', 'is_html_rule', 'is_exception',
                 'raw_options', 'options', '_options_keys', 'rule_text',
                 'regex', 'regex_re']

    def __init__(self, rule_text):
        self.raw_rule_text = rule_text
        self.regex_re = None

        rule_text = rule_text.strip()
        self.is_comment = not rule_text or rule_text.startswith(('!', '[Adblock'))
        if self.is_comment:
            self.is_html_rule = self.is_exception = False
        else:
            self.is_html_rule = '##' in rule_text or '#@#' in rule_text  # or rule_text.startswith('#')
            self.is_exception = rule_text.startswith('@@')
            if self.is_exception:
                rule_text = rule_text[2:]

        if not self.is_comment and '$' in rule_text:
            rule_text, options_text = rule_text.split('$', 1)
            self.raw_options = self._split_options(options_text)
            self.options = dict(self._parse_option(opt) for opt in self.raw_options)
        else:
            self.raw_options = []
            self.options = {}
        self._options_keys = frozenset(self.options.keys()) - set(['match-case'])

        self.rule_text = rule_text

        if self.is_comment or self.is_html_rule:
            # TODO: add support for HTML rules.
            # We should split the rule into URL and HTML parts,
            # convert URL part to a regex and parse the HTML part.
            self.regex = ''
        else:
            self.regex = self.rule_to_regex(rule_text)

    def match_url(self, url, options=None):
        """
        Return if this rule matches the URL.

        What to do if rule is matched is up to developer. Most likely
        ``.is_exception`` attribute should be taken in account.
        """
        options = options or {}
        for optname in self.options:
            if optname == 'match-case':  # TODO
                continue

            if optname not in options:
                raise ValueError("Rule requires option %s" % optname)

            if optname == 'domain':
                if not self._domain_matches(options['domain']):
                    return False
                continue

            if options[optname] != self.options[optname]:
                return False

        return self._url_matches(url)

    def _domain_matches(self, domain):
        domain_rules = self.options['domain']
        for domain in _domain_variants(domain):
            if domain in domain_rules:
                return domain_rules[domain]
        return not any(domain_rules.values())

    def _url_matches(self, url):
        if self.regex_re is None:
            self.regex_re = re.compile(self.regex)
        return bool(self.regex_re.search(url))

    def matching_supported(self, options=None):
        """
        Return whether this rule can return meaningful result,
        given the `options` dict. If some options are missing,
        then rule shouldn't be matched against, and this function
        returns False.

        No options:
        >>> rule = AdblockRule("swf|")
        >>> rule.matching_supported({})
        True

        Option is used in the rule, but its value is not available
        at matching time:
        >>> rule = AdblockRule("swf|$third-party")
        >>> rule.matching_supported({})
        False

        Option is used in the rule, and option value is available
        at matching time:
        >>> rule = AdblockRule("swf|$third-party")
        >>> rule.matching_supported({'domain': 'example.com', 'third-party': False})
        True

        Rule is a comment:
        >>> rule = AdblockRule("!this is not a rule")
        >>> rule.matching_supported({})
        False

        """
        if self.is_comment:
            return False

        if self.is_html_rule:  # HTML rules are not supported yet
            return False

        options = options or {}
        keys = set(options.keys())
        if not keys.issuperset(self._options_keys):
            # some of the required options are not given
            return False

        return True

    @classmethod
    def _split_options(cls, options_text):
        return cls.OPTIONS_SPLIT_RE.split(options_text)

    @classmethod
    def _parse_domain_option(cls, text):
        domains = text[len('domain='):]
        parts = domains.replace(',', '|').split('|')
        return dict(cls._parse_option_negation(p) for p in parts)

    @classmethod
    def _parse_option_negation(cls, text):
        return (text.lstrip('~'), not text.startswith('~'))

    @classmethod
    def _parse_option(cls, text):
        if text.startswith("domain="):
            return ("domain", cls._parse_domain_option(text))
        return cls._parse_option_negation(text)

    @classmethod
    def rule_to_regex(cls, rule):
        """
        Convert AdBlock rule to a regular expression.
        """
        if not rule:
            return rule

        # Check if the rule isn't already regexp
        if rule.startswith('/') and rule.endswith('/'):
            if len(rule) > 1:
                rule = rule[1:-1]
            else:
                raise AdblockParsingError('Invalid rule')
            return rule

        # escape special regex characters
        rule = re.sub(r"([.$+?{}()\[\]\\])", r"\\\1", rule)

        # XXX: the resulting regex must use non-capturing groups (?:
        # for performance reasons; also, there is a limit on number
        # of capturing groups, no using them would prevent building
        # a single regex out of several rules.

        # Separator character ^ matches anything but a letter, a digit, or
        # one of the following: _ - . %. The end of the address is also
        # accepted as separator.
        rule = rule.replace("^", r"(?:[^\w\d_\-.%]|$)")

        # * symbol
        rule = rule.replace("*", ".*")

        # | in the end means the end of the address
        if rule[-1] == '|':
            rule = rule[:-1] + '$'

        # || in the beginning means beginning of the domain name
        if rule[:2] == '||':
            # XXX: it is better to use urlparse for such things,
            # but urlparse doesn't give us a single regex.
            # Regex is based on http://tools.ietf.org/html/rfc3986#appendix-B
            if len(rule) > 2:
                #          |            | complete part     |
                #          |  scheme    | of the domain     |
                rule = r"^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?" + rule[2:]

        elif rule[0] == '|':
            # | in the beginning means start of the address
            rule = '^' + rule[1:]

        # other | symbols should be escaped
        # we have "|$" in our regexp - do not touch it
        rule = re.sub(r"(\|)[^$]", r"\|", rule)

        return rule

    def __repr__(self):
        return "AdblockRule(%r)" % self.raw_rule_text


class AdblockRules(object):
    """
    AdblockRules is a class for checking URLs against multiple AdBlock rules.

    It is more efficient to use AdblockRules instead of creating AdblockRule
    instances manually and checking them one-by-one because AdblockRules
    optimizes some common cases.
    """

    def __init__(self, rules, supported_options=None, skip_unsupported_rules=True, rule_cls=AdblockRule):

        if supported_options is None:
            self.supported_options = rule_cls.BINARY_OPTIONS + ['domain']
        else:
            self.supported_options = supported_options

        self.rule_cls = rule_cls
        self.skip_unsupported_rules = skip_unsupported_rules

        _params = dict((opt, True) for opt in self.supported_options)
        self.rules = [
            r for r in (
                r if isinstance(r, rule_cls) else rule_cls(r)
                for r in rules
            )
            if (r.regex or r.options) and r.matching_supported(_params)
        ]

        # "advanced" rules are rules with options,
        # "basic" rules are rules without options
        advanced_rules, basic_rules = split_data(self.rules, lambda r: r.options)

        # Rules with domain option are handled separately:
        # if user passes a domain we can discard all rules which
        # require another domain. So we build an index:
        # {domain: [rules_which_require_it]}, and only check
        # rules which require our domain. If a rule doesn't require any
        # domain.
        # TODO: what about ~rules? Should we match them earlier?
        domain_required_rules, non_domain_rules = split_data(
            advanced_rules,
            lambda r: (
                'domain' in r.options
                and any(r.options["domain"].values())
            )
        )

        # split rules into blacklists and whitelists
        self.blacklist, self.whitelist = self._split_bw(basic_rules)
        self.blacklist_re = _combined_regex([r.regex for r in self.blacklist])
        self.whitelist_re = _combined_regex([r.regex for r in self.whitelist])

        self.blacklist_with_options, self.whitelist_with_options = \
            self._split_bw(non_domain_rules)
        self.blacklist_require_domain, self.whitelist_require_domain = \
            self._split_bw_domain(domain_required_rules)

    def should_block(self, url, options=None):
        # TODO: group rules with similar options and match them in bigger steps
        options = options or {}
        if self._is_whitelisted(url, options):
            return False
        if self._is_blacklisted(url, options):
            return True
        return False

    def _is_whitelisted(self, url, options):
        return self._matches(
            url, options,
            self.whitelist_re,
            self.whitelist_require_domain,
            self.whitelist_with_options
        )

    def _is_blacklisted(self, url, options):
        return self._matches(
            url, options,
            self.blacklist_re,
            self.blacklist_require_domain,
            self.blacklist_with_options
        )

    def _matches(self, url, options,
                 general_re, domain_required_rules, rules_with_options):
        """
        Return if ``url``/``options`` are matched by rules defined by
        ``general_re``, ``domain_required_rules`` and ``rules_with_options``.

        ``general_re`` is a compiled regex for rules without options.

        ``domain_required_rules`` is a {domain: [rules_which_require_it]}
        mapping.

         ``rules_with_options`` is a list of AdblockRule instances that
        don't require any domain, but have other options.
        """
        if general_re and general_re.search(url):
            return True

        rules = []
        if 'domain' in options and domain_required_rules:
            src_domain = options['domain']
            for domain in _domain_variants(src_domain):
                if domain in domain_required_rules:
                    rules.extend(domain_required_rules[domain])

        rules.extend(rules_with_options)

        if self.skip_unsupported_rules:
            rules = [rule for rule in rules if rule.matching_supported(options)]

        return any(rule.match_url(url, options) for rule in rules)

    @classmethod
    def _split_bw(cls, rules):
        return split_data(rules, lambda r: not r.is_exception)

    @classmethod
    def _split_bw_domain(cls, rules):
        blacklist, whitelist = cls._split_bw(rules)
        return cls._domain_index(blacklist), cls._domain_index(whitelist)

    @classmethod
    def _domain_index(cls, rules):
        result = defaultdict(list)
        for rule in rules:
            domains = rule.options.get('domain', {})
            for domain, required in domains.items():
                if required:
                    result[domain].append(rule)
        return dict(result)


def _domain_variants(domain):
    """
    >>> list(_domain_variants("foo.bar.example.com"))
    ['foo.bar.example.com', 'bar.example.com', 'example.com']
    >>> list(_domain_variants("example.com"))
    ['example.com']
    >>> list(_domain_variants("localhost"))
    ['localhost']
    """
    parts = domain.split('.')
    if len(parts) == 1:
        yield parts[0]
    else:
        for i in range(len(parts), 1, -1):
            yield ".".join(parts[-i:])


def _combined_regex(regexes, flags=re.IGNORECASE):
    """
    Return a compiled regex combined (using OR) from a list of ``regexes``.
    If there is nothing to combine, None is returned.
    """
    joined_regexes = "|".join(r for r in regexes if r)
    if not joined_regexes:
        return None

    return re.compile(joined_regexes, flags=flags)


def split_data(iterable, pred):
    """
    Split data from ``iterable`` into two lists.
    Each element is passed to function ``pred``; elements
    for which ``pred`` returns True are put into ``yes`` list,
    other elements are put into ``no`` list.

    >>> split_data(["foo", "Bar", "Spam", "egg"], lambda t: t.istitle())
    (['Bar', 'Spam'], ['foo', 'egg'])
    """
    yes, no = [], []
    for d in iterable:
        if pred(d):
            yes.append(d)
        else:
            no.append(d)
    return yes, no


# ------------------------------------------------
# An mitmproxy adblock script!
# (Required python modules: adblockparser)
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

import datetime, os, re
import urllib.request
from mitmproxy import http
from glob import glob


class AdBlock:

    def __init__(self):
        self.IMAGE_MATCHER      = re.compile(r"\.(png|jpe?g|gif)$")
        self.SCRIPT_MATCHER     = re.compile(r"\.(js)$")
        self.STYLESHEET_MATCHER = re.compile(r"\.(css)$")

        __dir__ = __file__.removesuffix('.py')
        __dir__ = os.path.join(__dir__, 'output', 'blocklists')

        if self.should_update_blocklists(__dir__):
            self.update_blocklists(__dir__)

        try:
            blocklists = glob(os.path.join(__dir__, '*'))
        except:
            blocklists = []

        if len(blocklists) > 0:
            self.rules = self.load_rules(blocklists)
        else:
            self.rules = None

    def should_update_blocklists(self, __dir__, max_age_in_days=7):
        try:
            fpath         = os.path.join(__dir__, '1.txt')
            file_mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(fpath))
            today         = datetime.datetime.today()
            age           = today - file_mod_time

            return (age.days > max_age_in_days)
        except:
            return True

    def update_blocklists(self, __dir__):
        default_blocklist_urls = []
        default_blocklist_urls.append('https://easylist-downloads.adblockplus.org/easylist.txt')
        # default_blocklist_urls.append('https://easylist-downloads.adblockplus.org/easyprivacy.txt')
        # default_blocklist_urls.append('https://easylist-downloads.adblockplus.org/fanboy-annoyance.txt')
        # default_blocklist_urls.append('https://easylist-downloads.adblockplus.org/fanboy-social.txt')

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

    def load_rules(self, blocklists=None):
        rules = AdblockRules(
            self.combined(blocklists),
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
