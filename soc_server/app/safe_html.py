"""Small allowlist sanitizer for optional Markdown rendering; no extra dependency."""
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit


class _Sanitizer(HTMLParser):
    tags = {"p", "br", "hr", "strong", "em", "b", "i", "code", "pre", "blockquote",
            "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "a",
            "table", "thead", "tbody", "tr", "th", "td"}
    blocked = {"script", "style", "iframe", "object", "svg", "math", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.suppressed = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.blocked:
            self.suppressed += 1
        if self.suppressed or tag not in self.tags:
            return
        safe_attrs = []
        if tag == "a":
            for key, value in attrs:
                if key == "href" and value:
                    normalized = "".join(c for c in value if ord(c) > 32)
                    try:
                        safe = urlsplit(normalized).scheme.lower() in ("", "http", "https", "mailto")
                    except ValueError:
                        safe = False
                    if safe:
                        safe_attrs.append('href="%s"' % escape(normalized, quote=True))
                elif key == "title" and value:
                    safe_attrs.append('title="%s"' % escape(value, quote=True))
        self.parts.append("<%s%s>" % (tag, " " + " ".join(safe_attrs) if safe_attrs else ""))

    def handle_endtag(self, tag):
        if tag in self.blocked:
            self.suppressed = max(0, self.suppressed - 1)
            return
        if not self.suppressed and tag in self.tags and tag not in ("br", "hr"):
            self.parts.append("</%s>" % tag)

    def handle_data(self, data):
        if not self.suppressed:
            self.parts.append(escape(data))


def sanitize_html(value):
    parser = _Sanitizer()
    parser.feed(value)
    parser.close()
    return "".join(parser.parts)
