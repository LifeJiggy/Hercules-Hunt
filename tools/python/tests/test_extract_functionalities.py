import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from extract_functionalities import FunctionalityExtractor, FormAnalyzer, LinkAnalyzer

class TestFormAnalyzer:
    def test_init(self):
        fa = FormAnalyzer()
        assert fa is not None

    def test_parse_basic_form(self):
        fa = FormAnalyzer()
        html = '<form action="/login" method="POST"><input name="user"><input name="pass" type="password"><button type="submit">Go</button></form>'
        forms = fa.parse(html, base_url="http://test.com")
        assert len(forms) >= 1
        f = forms[0]
        assert f["action"] == "/login" or "login" in f["action"]
        assert len(f["inputs"]) >= 2

    def test_parse_form_with_select(self):
        fa = FormAnalyzer()
        html = '<form action="/api"><select name="role"><option value="admin">Admin</option><option value="user">User</option></select></form>'
        forms = fa.parse(html, base_url="http://test.com")
        assert len(forms) >= 1
        inputs = forms[0]["inputs"]
        selects = [i for i in inputs if i.get("type") == "select"]
        assert len(selects) >= 1

    def test_parse_empty_html(self):
        fa = FormAnalyzer()
        forms = fa.parse("<html><body>No forms here</body></html>", "http://test.com")
        assert forms == []

class TestLinkAnalyzer:
    def test_init(self):
        la = LinkAnalyzer()
        assert la is not None

    def test_extract_links(self):
        la = LinkAnalyzer()
        html = '<a href="/page1">Page 1</a><a href="/page2">Page 2</a><a href="https://external.com">Ext</a>'
        links = la.extract(html, base_url="http://test.com")
        assert len(links) >= 2

    def test_extract_with_onclick(self):
        la = LinkAnalyzer()
        html = '<a href="#" onclick="submitForm()">Click</a>'
        links = la.extract(html, base_url="http://test.com")
        assert len(links) >= 1

    def test_extract_empty(self):
        la = LinkAnalyzer()
        links = la.extract("<html></html>", "http://test.com")
        assert links == []

class TestFunctionalityExtractor:
    def test_init_defaults(self):
        ext = FunctionalityExtractor()
        assert ext.depth == 2

    def test_init_custom(self):
        ext = FunctionalityExtractor(depth=5, include_hidden=False)
        assert ext.depth == 5
        assert ext.include_hidden is False

    def test_extract_buttons(self):
        ext = FunctionalityExtractor()
        html = '<button>Save</button><button type="submit">Submit</button><input type="submit" value="Go">'
        buttons = ext._extract_buttons(html)
        assert len(buttons) >= 2

    def test_extract_inputs(self):
        ext = FunctionalityExtractor()
        html = '<input name="email" type="email"><input name="file" type="file"><textarea name="bio"></textarea>'
        inputs = ext._extract_inputs(html)
        assert len(inputs) >= 2
        names = [i.get("name") for i in inputs]
        assert "email" in names

    def test_extract_events(self):
        ext = FunctionalityExtractor()
        html = '<div onclick="handler()" onchange="changed()" onmouseover="hover()">test</div>'
        events = ext._extract_event_handlers(html)
        assert len(events) >= 2

    def test_get_summary_empty(self):
        ext = FunctionalityExtractor()
        s = ext.get_summary()
        assert s["total_forms"] >= 0

    def test_allow_insecure(self):
        ext = FunctionalityExtractor(allow_insecure=True)
        assert ext.allow_insecure is True

    def test_url_length_limit(self):
        ext = FunctionalityExtractor()
        with pytest.raises(ValueError):
            ext._validate_url("http://x.com/" + "a" * 9000)

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "extract_functionalities", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
