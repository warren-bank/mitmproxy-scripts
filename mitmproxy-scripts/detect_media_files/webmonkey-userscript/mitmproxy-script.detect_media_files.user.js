// ==UserScript==
// @name         PCAPdroid mitm: Detected Media File Requests
// @description  Enable WebMonkey functionality on the list of detected media file requests produced by the PCAPdroid mitm addon: "detect_media_files"
// @version      1.0.0
// @match        https://example.com/detect_media_files.html
// @icon         https://github.com/emanuele-f/PCAPdroid-mitm/raw/v0.14/app/src/main/res/mipmap-mdpi/ic_launcher.png
// @run-at       document-start
// @grant        unsafeWindow
// @homepage     https://github.com/warren-bank/mitmproxy-scripts
// @supportURL   https://github.com/warren-bank/mitmproxy-scripts/issues
// @downloadURL  https://github.com/warren-bank/mitmproxy-scripts/raw/master/mitmproxy-scripts/detect_media_files/webmonkey-userscript/mitmproxy-script.detect_media_files.user.js
// @updateURL    https://github.com/warren-bank/mitmproxy-scripts/raw/master/mitmproxy-scripts/detect_media_files/webmonkey-userscript/mitmproxy-script.detect_media_files.user.js
// @namespace    warren-bank
// @author       Warren Bank
// @copyright    Warren Bank
// ==/UserScript==

if (typeof GM_loadUrl === 'function')
  unsafeWindow.GM_loadUrl = GM_loadUrl

if (typeof GM_resolveUrl === 'function')
  unsafeWindow.GM_resolveUrl = GM_resolveUrl

if (typeof GM_startIntent === 'function')
  unsafeWindow.GM_startIntent = GM_startIntent
