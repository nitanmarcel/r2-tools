#!/home/nitanmarcel/.pyenv/shims/python
import r2pipe
import frida

import os

import argparse
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse

USAGE = f"""
[spawn/attach]://[usb/local]/[appname/pid]

Attach to a local pid: attach://1234

Spawn a local application: attach://'App Name'

Same can be used for usb devices, but using /usb/ befor the app name

attach://usb/1234

"""


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument('command', help=USAGE)

    args = parser.parse_args()

    parsed_url = urlparse(args.command)

    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    path = parsed_url.path

    if not scheme or scheme not in ['spawn', 'attach']:
        print(USAGE)
    elif not netloc:
        print(USAGE)
    else:
        _type = 'attach'
        _target = 'local'
        appname = ''
        if scheme == 'spawn':
            _type = 'spawn'
        else:
            _type = 'attach'
        if netloc not in ['usb', 'local'] or not path:
            appname = netloc
            if path:
                appname = appname + path
        elif netloc == 'usb':
            _target = 'usb'
        if scheme == 'spawn':
            _type = 'spawn'
        if path:
            appname = path[1:]

    return _type, _target, appname

# #!pipe ./frd.py usb spawn com.openai.chatgpt


BASE_TEMPLATE = """
console.log('LOADED')

var hooked = false
const library = '$(LIBRARY)'

function doHook() {
    if (!hooked) {
        try {
            Module.ensureInitialized(library);
            hooked = true
            var base = Module.findBaseAddress(library)

            $(INTERCEPT)
        } catch (err) {
            throw err
        }
    }
}

setInterval(doHook, 0)
"""

INTERCEPT_TEMPLATE = """
var address = $(ADDRESS)
var target = base.add(address)
Interceptor.attach(target, {
    onEnter: function(args) {
        this._target = target
        console.log('\\n', target, 'ENTER')
        console.log('----------------------------------')
        var aArgs = $(ARGS)
        aArgs.forEach((element, index) => {
            var arg = args[index]
            // Try to guess the type
            try {
                arg = args[index].toUInt32()
            } catch {

            }
            try {
                arg = Memory.readUtf8String(args[index])
            } catch {

            }
            console.log('\\n', 'ARG', '(' + element.name + ')', ':')
            console.log('++++++++++++++++++++++++++++++++++')
            console.log(arg)
            console.log('**********************************\\n')
        });
    },
    onLeave: function(retval) {
        console.log(this._target, 'LEAVE')
        var res = retval

        // Try to guess the type
        try {
            res = retval.toUInt32()
        } catch {

        }
        try {
            res = Memory.readUtf8String(retval)
        } catch {

        }
        console.log('++++++++++++++++++++++++++++++++++')
        console.log('RETVAL ', res)
        console.log('**********************************\\n')
    }
})

"""


def main():
    target, device, appname = parse_args()

    r2 = r2pipe.open()

    info = r2.cmdj('ij')
    library = os.path.basename(info['core']['file'])

    address = r2.cmd('s')

    args = r2.cmdj('afvj %s' % address)

    intercept_script = ""
    aargs = []
    if args:
        for arg in args['reg']:
            name, type = arg['name'], arg['type']
            aargs.append({'name': name, 'type': type})

    intercept_script = INTERCEPT_TEMPLATE.replace(
        '$(ADDRESS)', address).replace('$(ARGS)', str(aargs))

    # $(LIBRARY) $(INTERCEPT)
    script = BASE_TEMPLATE.replace('$(LIBRARY)', library).replace(
        '$(INTERCEPT)', intercept_script)

    if device == 'local':
        device = frida.get_local_device()
    else:
        device = frida.get_usb_device()

    if target == 'spawn':
        pid = device.spawn(appname)
    else:
        pid = device.attach(int(appname) if appname.isdigit() else appname)

    session = device.attach(pid)

    script = session.create_script(script)
    script.load()

    device.resume(pid)

    input('Press any key to stop : ')

    try:
        script.unload()
    except (KeyboardInterrupt, frida.InvalidOperationError):
        pass


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(exc.__class__.__name__, exc, sep=' : ')
