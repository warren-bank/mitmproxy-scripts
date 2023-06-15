import json
from importlib import import_module
from glob import glob
from os.path import basename, dirname, isfile, join

def init():
    global addons
    scripts = get_scripts()
    initialize_module(scripts)
    addons = load_scripts(scripts)

def get_scripts():
    scripts = glob(join(dirname(__file__), "*.py"))
    scripts = [ basename(f)[:-3] for f in scripts if isfile(f) and (f != __file__) and not f.endswith('__init__.py') ]
    return scripts

def initialize_module(scripts):
    __dir__  = __file__[:-3]
    __init__ = join(__dir__, '__init__.py')
    file = open(__init__, mode='w+t', encoding='utf-8')
    for script in scripts:
        file.write('import ..' + script + "\n")
    file.write("\n" + '__all__ = ' + json.dumps(scripts) + "\n")
    file.close()

def load_scripts(scripts):
    package = basename(__file__)[:-3]
    addons = []
    for mod_name in scripts:
        mod = import_module(mod_name, package=package)
        if mod and mod.addons and isinstance(mod.addons, list):
            addons.extend(mod.addons)
    return addons

init()

# print("\n".join(map(str, addons)))
