import os, cgi, re, string, hashlib, hmac, time, logging, locale, random, wsgiref.handlers, urllib, datetime
from google.appengine.ext import webapp, db
from google.appengine.ext.webapp import template
from google.appengine.api import urlfetch, memcache
from django.utils import simplejson
from bucky_util import *

buckybase_hostname = "http://buckybase.appspot.com"

def main():
    app = webapp.WSGIApplication(
        [(r"^/$", MainHandler),
         (r"^/new$", NewHandler),
         (r"^/save_new$", SaveNewHandler),
         (r"^/save_edit$", SaveEditHandler),
         (r"^/register$", RegisterHandler),
         (r"^/login$", LoginHandler),
         (r"^/logout$", LogoutHandler),
         (r"^/password$", PasswordHandler),
         (r"^/sys$", SysHandler),
         ("^/all/([^/]+)$", AllHandler),
         ("^/([^/]+)[/]?$", SiteHandler),
         ("^/([^/]+)/([^/]+)[/]?$", PageHandler),
         ("^/([^/]+)/([^/]+)/([^/]+)[/]?$", FieldHandler),
         ("^/([^/]+)/([^/]+)/([^/]+)/of[/]?$", InvFieldHandler),
         ],
        debug=True)
    wsgiref.handlers.CGIHandler().run(app)

class BuckyHandler(webapp.RequestHandler):
    def tmpl(self, name, values=None):
        if values is None:
            values = {}
        values["current_username"] = current_username(self.request)
        path = os.path.join(os.path.dirname(__file__), "tmpl/%s.html" % name)
        self.response.out.write(template.render(path, values))

class BuckyHttpError(Exception):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
    def __str__(self):
        return "%s %s" % (self.code, self.msg)

#### Registration and login

# Users are stored as top-level entities whose key names are their usernames

class User(db.Model):
    email = db.StringProperty()
    shadow = db.StringProperty()
    salt = db.StringProperty()

def shadow_password(salt, password):
    return hashlib.sha256(salt + password).hexdigest()

def user_url(username):
    assert (len(username) > 0)
    return "/%s" % username

reserved_usernames = set([
    "all", # handler; used in tag: URIs of AllHandler feeds
    "api",
    "doc",
    "docs",
    "buckybase",
    "feed", # used in tag: URI of MainHandler feed
    "feeds",
    "guide",
    "help",
    "hot",
    "login", # handler
    "logout", # handler
    "manual",
    "new", # handler
    "page",
    "password", # handler
    "pool",
    "pools",
    "recent",
    "register", # handler
    "save_edit", # handler
    "save_new", # handler
    "settings",
    "static", # static files under ./static
    "sys", # handler and xmlns
    "system", # protected static files under ./system
    "tag",
    "users",
    "www",
    ])

username_re = re.compile("^[a-z]([-a-z0-9]*[a-z0-9])?$")

def validate_username(username):
    """Usernames have to conform to a subset of the syntax for DNS
    hostname labels (they cannot consist only of numbers, as hostnames
    can)."""
    if (len(username) == 0):
        raise ValueError, "Please use a non-blank username"
    if (len(username) > 63):
        raise ValueError, "Please use a username shorter than 64 characters"
    if username_re.match(username) == None:
        raise ValueError, "Please use a username that starts with a-z, contains only a-z, 0-9, and -, and does not end with -"
    if username in reserved_usernames:
        raise ValueError, "Sorry, username already taken."

def validate_email(email):
    if (len(email) == 0):
        raise ValueError, "Please fill in an email address"
    if (not ("@" in email)):
        raise ValueError, "Please fill in an email address"

def validate_password(password):
    if (len(password) == 0):
        raise ValueError, "Please use a non-blank password"

def validate_passwords(password, password2):
    validate_password(password)
    validate_password(password2)
    if (password != password2):
        raise ValueError, "Passwords do not match"

def request_username(request):
    """Registration and login handlers both use 'username' as URL argument."""
    username = request.get("username")
    if username != None:
        return string.lower(username)
    else:
        return None

def register_user_tx(username, email, password):
    if (User.get_by_key_name(username) != None):
        raise ValueError, "Sorry, username already taken"
    salt = str(random.random())
    assert (len(salt) > 0)
    shadow = shadow_password(salt, password)
    user = User(key_name=username, email=email, salt=salt, shadow=shadow)
    user.put()

class RegisterHandler(BuckyHandler):
    def get(self):
        self.tmpl("register")
    def post(self):
        try:
            username = request_username(self.request)
            email = self.request.get("email")
            password = self.request.get("password")
            password2 = self.request.get("password2")
            validate_username(username)
            validate_email(email)
            validate_passwords(password, password2)
            db.run_in_transaction(register_user_tx, username, email, password)
            login_user(self.response, username)
            self.redirect(user_url(username))
        except ValueError, e:
            self.tmpl("register", { "error": e.message,
                                    "username": username,
                                    "email": email })

class LoginHandler(BuckyHandler):
    def get(self):
        self.tmpl("login")
    def post(self):
        if get_secure_key() == "nologin":
            raise BuckyHttpError, ("500", "Login temporarily disabled. Please try again later.")
        try:
            username = request_username(self.request)
            password = self.request.get("password")
            validate_username(username)
            validate_password(password)
            user = User.get_by_key_name(username)
            if (user == None):
                raise ValueError, "Sorry, that username does not exist"
            shadow = shadow_password(user.salt, password)
            if (shadow != user.shadow):
                raise ValueError, "Sorry, wrong password"
            login_user(self.response, username)
            self.redirect(user_url(username))
        except ValueError, e:
            self.tmpl("login", { "error": e.message,
                                 "username": username })

class LogoutHandler(BuckyHandler):
    def get(self):
        logging.debug("Logging out %s", current_username(self.request))
        expsecs = int(time.time()) - (60*60*24*365)
        expires = cookie_strftime(time.gmtime(expsecs))
        self.response.headers.add_header("Set-cookie",
                                         "%s=over; expires=%s" % (session_cookie_name, expires))
        self.redirect("/")

#### Stateless session cookie

# The session cookie consists of the username, the expiration time in
# seconds GMT when the session expires, and a HMAC of the username and
# the expiration time that uses a secure key stored in the datastore.
#
# Recipe from "Dos and Don'ts of Client Authentication on the Web"
# http://cookies.lcs.mit.edu/pubs/webauth.html

def login_user(response, username):
    cookie = session_cookie(username)
    response.headers.add_header("Set-cookie", cookie)

session_cookie_name = "session"
session_duration_minutes = 60

def session_cookie(username):
    expsecs = int(time.time()) + (60 * session_duration_minutes)
    expires = cookie_strftime(time.gmtime(expsecs))
    exp = str(expsecs)
    digest = session_cookie_digest(username, exp)
    return str("%s=%s; expires=%s" % (session_cookie_name,
                                      username + "_" + exp + "_" + digest,
                                      expires))

def session_cookie_digest(username, exp):
    assert (len(username) > 0)
    assert (len(exp) > 0)
    return hmac.new(get_secure_key(), username + exp, hashlib.sha256).hexdigest()

def cookie_strftime(gmtime):
    return time.strftime("%a, %d-%b-%Y %H:%M:%S GMT", gmtime)

def current_username(request):
    """Extracts, checks, and caches the username stored in the session cookie."""

    if "username" in request.environ:
        return request.environ["username"]
    else:
        # if we fail (i.e. "return None") somewhere in the code below,
        # the next time current_username is called it will quickly
        # return None.
        request.environ["username"] = None

    if get_secure_key() == "nologin":
        return None

    if (session_cookie_name in request.cookies):
        cookie = request.cookies[session_cookie_name]
    else:
        return None
    vals = cookie.split("_")
    if (len(vals) != 3):
        logging.error("Strange session cookie: %s", cookie)
        return None
    username, exp, digest = vals
    if (session_cookie_digest(username, exp) != digest):
        logging.error("Wrong session cookie digest: %s", cookie)
        return None
    expsecs = locale.atoi(exp)
    if (time.time() > expsecs):
        # expired
        return None

    request.environ["username"] = username
    return username

#### Cross-site request forgery (XSRF) protection

def xsrf_key(request):
    """
    Simply use the session cookie's contents as Anti-XSRF measure.  It
    is embedded in a hidden form field and save handlers check that it
    equals the session cookie.
    """
    if (session_cookie_name in request.cookies):
        return request.cookies[session_cookie_name]
    else:
        raise BuckyHttpError, ("500", "No session cookie")

def xsrf_check(request):
    """
    Called before every save.  Ensures that the user-provided XSRF key
    matches the session cookie.  Note that it doesn't check whether
    the session is still valid.  Thus, a session validity check
    (i.e. checking that `current_username` is not None) must always be
    performed in addition to a XSRF check.
    """
    if (session_cookie_name in request.cookies):
        cookie = request.cookies[session_cookie_name]
        xsrf_key = request.get("xsrf_key")
        if not xsrf_key:
            raise BuckyHttpError, ("500", "No XSRF key")
        if not (cookie == xsrf_key):
            raise BuckyHttpError, ("500", "XSRF key doesn't match session cookie")
    else:
        raise BuckyHttpError, ("500", "No session cookie")

# The secure key is stored in a singleton entity created at startup.
# It is simply a digest of a random number.
#
# To refresh/revoke the key it is necessary to delete it using the App
# Engine data viewer, and upload a new version of the application
# (with a nonsignificant change to the bucky.py file -- this is
# required to remove the secure_key from the App Engine Python module
# cache mechanism.)

secure_key = None

class ZSecret(db.Model):
    secure_key = db.StringProperty()

def get_secure_key():
    global secure_key
    if not secure_key:
        raise Error, "no secure key"
    return secure_key

def setup_secret_tx():
    global secure_key
    secret = ZSecret.get_by_key_name("secret")
    if (secret == None):
        new_secure_key = hashlib.sha256(str(random.random())).hexdigest()
        secret = ZSecret(key_name="secret", secure_key=new_secure_key)
        secret.put()
    # Note: if the transaction fails, secure_key will still hold the
    # key.  This is a) highly unikely, b) happens only should the key
    # be revoked c) doesn't matter -- people will simply need to login
    # again.
    secure_key = secret.secure_key

#### Structured tags parsing & rendering

tag_re = re.compile("^([^:]+):(.*)$")

def line_tag(line):
    """Parses a line into a 2-tuple (name, [value1, value2, ...]),
    or None if the line doesn't define a tag."""
    global tag_re
    m = tag_re.match(line)
    if m:
        fieldname = m.group(1).strip()
        if len(fieldname) > 0:
            return (fieldname, list(x.strip() for x in m.group(2).split(",")))
    return None

def text_tags(text):
    """Returns a 'canonicalized' dict holding the tags of a text.  The
    dict's keys are the tag names, while the values are lists of tag
    values (in the order they appear in the text; may contain
    duplicates).  This is the main entry point for getting at a text's
    embedded data."""
    tags = {}
    for line in text.splitlines():
        tag = line_tag(line)
        if tag:
            name, values = tag
            tags.setdefault(name, []).extend(values)
        else:
            # break on first non-tag line
            break
    return tags

#### Pages

# Pages of a user are put under a (empty) top-level Site object whose
# key name is the user's username.
class Site(db.Model):
    pass

# A page's key name is the slugified title.  However, we still need to
# store the slug redundantly in the page to be able to use it in
# queries.
class Page(db.Expando):
    title = db.StringProperty()
    text = db.TextProperty()
    username = db.StringProperty()
    updated = db.DateTimeProperty()
    slug = db.StringProperty()

    # Additionally, a page contains dynamic properties for backlinks.
    # Such backlink properties consist of the string "bl_" and the
    # slugified tag name of the backlink, e.g. "bl_street-address" for
    # a tag named "street address".  The value of a backlink property
    # is a list, whose first element is the non-slugified tag name,
    # and whose later elements are the titles of pages linking to the
    # entity.

    # fixme: currently the site a page is in is somewhat entangled
    # with the username of the page. however, the two should be
    # separate, so that it would be possible for e.g. a user to have
    # multiple sites, or multiple users editing pages in one site.

    def url(self):
        return page_url(self.username, self.title)

    def edit_url(self):
        return page_url(self.username, self.title) + "?e"

    def all_url(self):
        """URL for this page from all users."""
        return all_url(self.title)

    def sitename(self):
        # fixme: should be self.parent_key().name()... but this may
        # conflict with some uses of unsaved pages.  check that.  one
        # data point: ad-hoc page creations could receive a parent
        # argument that is a key.  then this could work, and username
        # and site would be split, and never the two shall meet
        # (again).  However, the docs say setting parent to a key (and
        # not a model) works, but in reality it does not.  So we are
        # stuck with this mess.
        return self.username

    def site_url(self):
        return "/" + urlenc(self.sitename())

    def user_page_url(self, username):
        """URL for this page from another user."""
        return page_url(username, self.title)

    def field_url(self, fieldname, inv=False):
        fieldname = slugify(fieldname)
        if inv:
            return self.url() + "/" + urlenc(fieldname) + "/of"
        else:
            return self.url() + "/" + urlenc(fieldname)
    
    def render_text(self):
        in_tags = True
        out = ["<p><table class=kv>"]
        for line in self.text.splitlines():
            if in_tags:
                tag = line_tag(line)
                if tag:
                    name, values = tag
                    out.append(self.render_field(name, values))
                else:
                    out.append(self.render_backlinks())
                    out.append("</table><p>")
                    out.append(cgi.escape(line)) # EVIL
                    in_tags = False
            else:
                if line == "":
                    out.append("<p>")
                else:
                    if line.startswith("http://"):
                        out.append(oembed_consume_frame(line))
                    else:
                        out.append(cgi.escape(line))
        if in_tags:
            out.append(self.render_backlinks())
            out.append("</table><p>")
        return "".join(out)

    def render_field(self, name, values, inv=False):
        return ("<tr><th align=right>%s:</th><td>%s</td></tr>" %
                (self.render_field_name(name, inv),
                 self.render_field_values(name, values, inv)))

    def render_field_name(self, name, inv=False):
        label = cgi.escape(name)
        if inv:
            label += " of"
        return ('<a href="%s" class=blue><nobr>%s</nobr></a>' %
                (cgi.escape(self.field_url(name, inv)), label))

    def render_field_values(self, name, values, inv=False):
        return ", ".join([self.render_field_value(name, value, inv) for value in values])

    def render_field_value(self, name, value, inv=False):
        value = value.lstrip()
        if value.startswith("http:") or value.startswith("https:"):
            value = cgi.escape(value)
            return ('<a href="%s" rel=nofollow>%s</a>' % (value, value))
        else:
            return ('<a href="%s" %s="%s">%s</a>' %
                    (cgi.escape(page_url(self.sitename(), value)),
                     rdfa_rel_or_rev(inv),
                     cgi.escape(rdfa_rel_for_fieldname(name), quote=True),
                     cgi.escape(value)))

    def render_backlinks(self):
        out = []
        prop_names = self.dynamic_properties()
        for prop_name in prop_names:
            if prop_name.startswith("bl_"):
                title_list = getattr(self, prop_name)
                tag_name = title_list[0]
                titles = title_list[1:]
                out.append(self.render_field(tag_name, titles, inv=True))
        return "".join(out)

    def updated_str(self):
        if self.updated and (self.updated != special_datetime):
            return datestr(self.updated)
        else:
            return ""

    ## Atom support
    def entry_title(self):
        return self.title
    def entry_author_name(self):
        return self.username
    def entry_author_uri(self):
        return buckybase_hostname + user_url(self.username)
    def entry_uri(self):
        return buckybase_hostname + self.url()
    def entry_content(self):
        return self.render_text()
    def entry_id(self):
        return ("tag:buckybase.appspot.com,2008-06:%s/%s" %
                (urlenc(self.sitename()), urlenc(slugify(self.title))))
    def entry_updated(self):
        if self.updated and (self.updated != special_datetime):
            return self.updated.strftime(atom_date_format)
        else:
            return atom_date_now()

rdfa_ns = "bb"

def rdfa_rel_for_fieldname(name):
    return rdfa_ns + ":" + urlenc(slugify(name))

def rdfa_rel_or_rev(inv):
    if inv:
        return "rev"
    else:
        return "rel"

atom_date_format = "%Y-%m-%dT%H:%M:%SZ"

def atom_date_now():
    return time.strftime(atom_date_format, time.gmtime())

def urlenc(str):
    return urllib.quote(str.encode("utf-8"), "").replace(".", "%2e")

def urldec(str):
    # The need for this double escaping escapes me.
    return urllib.unquote(urllib.unquote(str)).decode("utf-8")

def slugify(str):
    # An important property is that slugify(str) == slugify(slugify(str))
    return str.lower().replace(" ", "-")

def page_url(username, title):
    return user_url(username) + "/" + urlenc(slugify(title))

def site_url(sitename):
    return "/" + urlenc(sitename)

def page_key_name(title_or_slug):
    """Returns the key name of a page, given its title.  Since key
    names starting with numbers and key names of the form __*__ are
    forbidden, we prepend a 'k' to the key name."""
    return "k" + slugify(title_or_slug)

def page_key(sitename, title_or_slug):
    return db.Key.from_path("Site", site_key_name(sitename),
                            "Page", page_key_name(title_or_slug))

def site_key_name(sitename):
    return "k" + sitename

def site_key(sitename):
    return db.Key.from_path("Site", site_key_name(sitename))

def all_url(title):
    return "/all/" + urlenc(slugify(title))

# Datastore strings can be 500 bytes -- does Python len(str) return
# bytes or code points?  In any case this is the number of title
# characters in the form that len() returns.
max_title_len = 255

def validate_title(str):
    if (len(str) == 0):
        raise ValueError, "Please use a longer title"
    if (len(str) > max_title_len):
        raise ValueError, "Please use a shorter title"

class NewHandler(BuckyHandler):
    def get(self):
        if (current_username(self.request) == None):
            self.redirect("/login")
            return
        self.tmpl("new", { "title": "",
                           "text": "",
                           "xsrf_key": xsrf_key(self.request) })

class PageHandler(BuckyHandler):
    def get(self, sitename, pagename):
        # note: pagename is not necessarily in slug format
        sitename = urldec(sitename)
        pagename = urldec(pagename)
        page = Page.get(page_key(sitename, pagename))
        if not page:
            page = Page(title=pagename,
                        username=sitename, # wrong, should be "", and parent=site_key(sitename)
                        slug=slugify(pagename),
                        updated=None,
                        text="")
        if self.request.GET.has_key("e"):
            if current_username(self.request) == sitename:
                self.tmpl("edit", { "page": page,
                                    "xsrf_key": xsrf_key(self.request) })
            else:
                logging.error("%s trying to edit %s's page %s",
                              current_username(self.request), sitename, pagename)
                raise BuckyHttpError, ("403", "Forbidden")
        else:
            self.tmpl("page", { "page": page })

# Pages created automatically because a page points to them during
# backlink processing have their updated date set to this datetime.
# This allows to distinguish them from user-updated pages and filter
# them out of some views.
special_datetime = datetime.datetime(1980, 11, 3)

def save_page_tx(title, text, username, sitename):
    validate_username(username)
    validate_title(title)
    site = Site.get_by_key_name(site_key_name(sitename))
    if not site:
        site = Site(key_name=site_key_name(sitename))
        site.put()

    # Diff new backlinks with backlinks of the existing page.
    ex_backlinks = {}
    ex_page = Page.get_by_key_name(page_key_name(title), parent=site)
    if ex_page:
        ex_backlinks = tags_backlinks(text_tags(ex_page.text))
    
    backlinks = tags_backlinks(text_tags(text))
    added, removed = diff_backlinks(backlinks, ex_backlinks)

    patch_backlinks(title, site, username, added, removed)

    # Update existing page if it exists.
    if not ex_page:
        ex_page = Page(parent=site,
                       key_name=page_key_name(title),
                       slug=slugify(title),
                       username=username)
    ex_page.title = title
    ex_page.text = text
    ex_page.updated=datetime.datetime.now()
    ex_page.put()

def patch_backlinks(title, site, username, added, removed):
    # Prepare set of slugs of affected pages.
    slugs = set()
    slugs.update(map(slugify, added.keys()))
    slugs.update(map(slugify, removed.keys()))
    
    # No self-backlinks.  I am not sure this is really needed, but
    # shouldn't hurt.
    slugs.discard(slugify(title))

    # Get all affected pages.
    if (len(slugs) > 0):
        pages = Page.get_by_key_name(map(page_key_name, slugs), parent=site)
    else:
        pages = []

    # Fill a dictionary mapping slugs to the pages we just retrieved.
    pages_dict = {}
    for page in pages:
        if page:
            pages_dict[page.slug] = page

    # If some of the pages we need don't exist, create them and put
    # them into the dict.  The thusly created pages have (sl)ugly
    # titles but they will be updated with more beautiful titles using
    # the backlink titles immediately.
    for slug in slugs:
        page = pages_dict.get(slug)
        if not page:
            page = Page(key_name=page_key_name(slug),
                        title=slug,
                        slug=slug,
                        updated=special_datetime, # mark as special.
                        parent=site,
                        username=username,
                        text="")
            pages_dict[page.slug] = page


    # First, remove backlinks.
    for page_title, tag_names in removed.items():
        page = pages_dict.get(slugify(page_title))
        for tag_name in tag_names:
            remove_backlink(page, tag_name, title)

    # Then, add new backlinks.  This order is needed because otherwise
    # `remove_backlink` would remove a backlink we just added.
    for page_title, tag_names in added.items():
        page = pages_dict.get(slugify(page_title))
        if not page:
            # The page must be a self-backlink.
            continue

        # The page is a "virtual" page and it still has an (sl)ugly
        # title.  Update its title with the more beautiful title we
        # have from the backlink.
        if (page.updated == special_datetime) and (page.title == page.slug):
            page.title = page_title

        # Usually there will only be one tag name that connects the
        # two pages but we strive for excellence.  The `title` is the
        # title of the new page.
        for tag_name in tag_names:
            add_backlink(page, tag_name, title)

    for page in pages_dict.values():
        if (page.updated == special_datetime) and (len(page.dynamic_properties()) == 0):
            page.delete()
        else:
            page.put()

def delete_page_tx(title, username, sitename):
    site = Site.get_by_key_name(site_key_name(sitename))
    if site:
        page = Page.get_by_key_name(page_key_name(title), parent=site)
        if page:
            backlinks = tags_backlinks(text_tags(page.text))
            patch_backlinks(title, site, username, {}, backlinks)
            if (len(page.dynamic_properties()) == 0):
                page.delete()
            else:
                page.updated = special_datetime
                page.text = ""
                page.put()

def add_backlink(page, tag_name, title):
    # Put the ("beautiful") tag name as first element into the list,
    # while the actual attribute name is slugified.
    title_list = getattr(page, backlink_property_name(tag_name), [tag_name])
    title_list.append(title) # fixme: what about duplicates? can it happen?
    setattr(page, backlink_property_name(tag_name), title_list)

def remove_backlink(page, tag_name, title):
    try:
        title_list = getattr(page, backlink_property_name(tag_name))
    except AttributeError:
        return
    titles = title_list[1:]
    if (len(titles) > 0):
        # Remove title from the titles list, using slug-equality.
        # Using slug-equality is important in case the user has
        # changed only the case of a title for example, which is not
        # treated as a rename of the page, because the slugs are still
        # equal.
        titles = filter(lambda t: slugify(t) != slugify(title), titles)

    if (len(titles) > 0):
        setattr(page, backlink_property_name(tag_name), [tag_name] + titles)
    else:
        delattr(page, backlink_property_name(tag_name))

def backlink_property_name(tag_name):
    return "bl_" + slugify(tag_name)

def tags_backlinks(tags):
    """
    Given a tags dict as returned by `text_tags`, returns its
    backlinks, a dictionary whose keys are the titles of linked pages
    and whose values are sets of tag names that link to them.  For
    example if a text has tags 'foo: bar' and 'quux: xyzzy, bar', its
    backlinks are {bar:[foo,quux], xyzzy:[quux]}.
    """
    backlinks = {}
    for tag_name, titles in tags.items():
        for title in titles:
            backlinks.setdefault(title, set([])).add(tag_name)
    return backlinks

def diff_backlinks(new, old):
    """
    Given two backlinks dicts `new` and `old`, as returned by
    `tags_backlinks`, return a 2-tuple whose first element ('added')
    is a backlinks dict of all backlinks that are in `new` but not in
    old, and whose second element ('removed'), is a dict of all
    backlinks that are in `old` but not in new.
    """
    return (backlink_difference(new, old),
            backlink_difference(old, new))

def backlink_difference(a, b):
    diff = {}
    for title, a_tag_names in a.items():
        b_tag_names = b.get(title, [])
        diff_tag_names = a_tag_names.difference(b_tag_names)
        if diff_tag_names:
            diff[title] = diff_tag_names
    return diff

class SaveNewHandler(BuckyHandler):
    def post(self):
        try:
            username = current_username(self.request)
            if not username:
                self.redirect("/login")
                return
            xsrf_check(self.request)
            title = self.request.get("title")
            text = self.request.get("text")
            # This guarantees that a user can only save into his site
            sitename = username
            db.run_in_transaction(save_page_tx, title, text, username, sitename)
            self.redirect(page_url(username, title))
        except ValueError, e:
            self.tmpl("new", { "error": e.message,
                               "title": title,
                               "text": text,
                               "xsrf_key": xsrf_key(self.request) })

class SaveEditHandler(BuckyHandler):
    def post(self):
        try:
            username = current_username(self.request)
            if not username:
                self.redirect("/login")
                return
            xsrf_check(self.request)
            title = self.request.get("title")
            old_title = self.request.get("old_title")
            text = self.request.get("text")
            delete = self.request.get("delete")
            # This guarantees that a user can only save into his site
            sitename = username
            if delete:
                # Note: we delete the old_title, i.e. the page the
                # user started editing with.
                db.run_in_transaction(delete_page_tx, old_title, username, sitename)
                self.redirect(user_url(username))
            else:
                db.run_in_transaction(save_page_tx, title, text, username, sitename)
                if (slugify(title) != slugify(old_title)):
                    db.run_in_transaction(delete_page_tx, old_title, username, sitename)
                self.redirect(page_url(username, title))
        except ValueError, e:
            page = Page(title=title,
                        username=username,
                        # wrong: site missing
                        slug=slugify(title),
                        updated=None,
                        text=text)
            self.tmpl("edit", { "error": e.message,
                                "old_title": old_title,
                                "page": page,
                                "xsrf_key": xsrf_key(self.request) })

#### Global handlers

class FeedHandler(BuckyHandler):
    def get_feed(self):
        view_as_table = (self.request.GET.get("view") == "table")
        if self.request.GET.has_key("feed"):
            self.response.headers["Content-type"] = "application/atom+xml"
            self.tmpl("feed",
                      { "feed": self,
                        "entries": self.pages,
                        "view_as_table": view_as_table })
        else:
            self.tmpl(self.tmpl_name(),
                      { "feed": self,
                        "pages": self.pages,
                        "view_as_table": view_as_table })
    def feed_url(self):
        return buckybase_hostname + self.feed_url_wo_hostname()
    def feed_html_url(self):
        return buckybase_hostname + self.feed_html_url_wo_hostname()
    def feed_url_wo_hostname(self):
        return self.feed_html_url_wo_hostname() + "?feed"
    def feed_updated(self):
        if (len(self.pages) > 0):
            return self.pages[0].entry_updated()
        else:
            return atom_date_now()
    # To be implemented by subclasses:
    def tmpl_name(self):
        raise Exception, "NIY"
    def feed_title(self):
        raise Exception, "NIY"
    def feed_html_url_wo_hostname(self):
        raise Exception, "NIY"
    def feed_id(self):
        raise Exception, "NIY"
    def feed_cse_url(self):
        raise Exception, "NIY"

    def table_view(self):

        # lose if fieldnames contain commas

        user_fieldnames = None
        if self.request.GET.has_key("fieldnames"):
            user_fieldnames = self.request.GET.get("fieldnames", "").split(",")
            user_fieldnames = [fn.strip(" ") for fn in user_fieldnames]

        # Parse all pages and calculate the popularity of fieldnames in one pass
        fieldnames2counts = {}
        pagelist = [] # contains pairs (page, tags)
        for page in self.pages:
            if page.text:
                tags = text_tags(page.text)
                for fieldname, values in tags.items():
                    fieldnames2counts[fieldname] = 1 + fieldnames2counts.get(fieldname, 0)
            else:
                tags = {}
            tags["title"] = [page.title] # lose: kicks out any property named title
            pagelist.append((page, tags))

        if user_fieldnames:
            fieldnames = user_fieldnames
        else:
            fieldnames2countslist = fieldnames2counts.items()
            fieldnames2countslist.sort(key=lambda pair: pair[1], reverse=True)
            fieldnames2countslist = fieldnames2countslist[0:7]
            fieldnames = map(lambda pair: pair[0], fieldnames2countslist)
            if not ("title" in fieldnames):
                fieldnames = ["title"] + fieldnames

        # Render these field values
        out = ["<table id=data class=data><thead><tr>"]
        for fieldname in fieldnames:
            out.append("<th>" + cgi.escape(fieldname) + "</th>")
        out.append("</tr></thead><tbody>")

        for page, tags in pagelist:
            out.append("""<tr about="%s">""" % cgi.escape(page.url()))
            for fieldname in fieldnames:
                values = map(lambda value: page.render_field_value(fieldname, value),
                             tags.get(fieldname, []))
                out.append("<td>" + (", ".join(values)) + "</td>")
            out.append("</tr>")

        out.append("</tbody></table>")

        fieldnames_str = cgi.escape(", ".join(fieldnames), quote=True)

        reset_fields_str = ""
        if user_fieldnames:
            reset_fields_str = """&nbsp;<a class=blue href="?view=table">reset fields</a>"""

        out.append("""
        <form action="" method=get style="padding: 1.5em .25em;">
        <input type=hidden name=view value=table>
        <input type=text name=fieldnames value="%s" style="width: 30em">
        <input type=submit value="show these fields">
        %s
        </form>
        """ % (fieldnames_str, reset_fields_str))

        return "".join(out)

class SiteHandler(FeedHandler):
    def get(self, sitename):
        self.sitename = urldec(sitename)
        q = Page.gql("WHERE ANCESTOR IS :site AND updated > :special ORDER BY updated DESC",
                     site=site_key(self.sitename),
                     special=special_datetime)
        self.pages = q.fetch(100)
        self.get_feed()
    def tmpl_name(self):
        return "site"
    def feed_title(self):
        return self.sitename
    def feed_html_url_wo_hostname(self):
        return site_url(self.sitename)
    def feed_id(self):
        return "tag:buckybase.appspot.com,2008-06:%s" % urlenc(self.sitename)
    def feed_cse_url(self):
        return cse_url(self.feed_html_url() + "/*", self.feed_title())

class AllHandler(FeedHandler):
    def get(self, pagename):
        self.title = urldec(pagename)
        q = Page.all()
        q = q.filter("slug =", slugify(self.title))
        q = q.order("-updated")
        self.pages = q.fetch(100)
        if (len(self.pages) > 0):
            # A nice touch: beautify the title if available
            self.title = self.pages[0].title
        self.get_feed()
    def tmpl_name(self):
        return "all"
    def feed_title(self):
        return self.title + " by all users"
    def feed_html_url_wo_hostname(self):
        return all_url(self.title)
    def feed_id(self):
        return "tag:buckybase.appspot.com,2008-06:all/" + urlenc(slugify(self.title))

def simulate_pages(sitename, titles):
    """Returns pages for a list of titles.  Fills in pseudo-pages
    (with title and sitename/username) for non-existing pages."""
    if (len(titles) == 0):
        return []
    pages = Page.get([page_key(sitename, title) for title in titles])

    def simulate_page(page, title):
        if page:
            return page
        else:
            # wrong: should be username="" and parent=site_key(sitename)
            return Page(title=title,
                        username=sitename,
                        updated=None,
                        slug=slugify(title),
                        text="")

    return map(simulate_page, pages, titles)

class FieldHandler(FeedHandler):
    def get(self, sitename, pagename, fieldname):
        self.sitename = urldec(sitename)
        self.pagename = urldec(pagename)
        self.fieldname = urldec(fieldname)
        self.page = Page.get(page_key(self.sitename, self.pagename))
        if self.page:
            tags = text_tags(self.page.text)
            titles = []
            for tag_name, values in tags.items():
                if slugify(tag_name) == slugify(self.fieldname):
                    titles.extend(values)
                    # A nice touch: beautify the field name if available
                    self.fieldname = tag_name
            self.pages = simulate_pages(self.sitename, titles)
            self.fieldtitle = self.fieldname
            self.get_feed()
        else:
            raise BuckyHttpError, ("404", "Not found")
    def tmpl_name(self):
        return "field"
    def feed_title(self):
        return "%s / %s / %s" % (self.page.sitename(), self.page.title, self.fieldtitle)
    def feed_html_url_wo_hostname(self):
        return self.page.field_url(self.fieldname)
    def feed_id(self):
        return ("tag:buckybase.appspot.com,2008-06:%s/%s/%s" %
                (urlenc(self.page.sitename()),
                 urlenc(slugify(self.page.title)),
                 urlenc(slugify(self.fieldname))))

class InvFieldHandler(FieldHandler):
    def get(self, sitename, pagename, fieldname):
        self.sitename = urldec(sitename)
        self.pagename = urldec(pagename)
        self.fieldname = urldec(fieldname)
        self.page = Page.get(page_key(self.sitename, self.pagename))
        if self.page:
            title_list = getattr(self.page,
                                 backlink_property_name(self.fieldname),
                                 [self.fieldname])
            tag_name = title_list[0]
            titles = title_list[1:]
            self.pages = simulate_pages(self.sitename, titles)
            self.fieldtitle = tag_name + " of"
            self.get_feed()
        else:
            raise BuckyHttpError, ("404", "Not found")
    def feed_html_url_wo_hostname(self):
        return self.page.field_url(self.fieldname, inv=True)
    def feed_id(self):
        return ("tag:buckybase.appspot.com,2008-06:%s/%s/%s/of" %
                (urlenc(self.page.sitename()),
                 urlenc(slugify(self.page.title)),
                 urlenc(slugify(self.fieldname))))

class MainHandler(FeedHandler):
    def get(self):
        q = Page.gql("WHERE updated > :special ORDER BY updated DESC",
                     special=special_datetime)
        self.pages = q.fetch(100)
        self.get_feed()
    def tmpl_name(self):
        return "main"
    def feed_title(self):
        return "recent changes"
    def feed_html_url_wo_hostname(self):
        return "/"
    def feed_id(self):
        return "tag:buckybase.appspot.com,2008-06:feed"
    def feed_cse_url(self):
        return cse_url(buckybase_hostname + "/*", "buckybase")

class PasswordHandler(BuckyHandler):
    def get(self):
        self.tmpl("password")
    def post(self):
        username_or_email = self.request.get("username_or_email")

# The sys handler is a catch-all for various handlers that don't need
# a pretty URL; it's purpose is to keep the URL processing efficient.

class SysHandler(BuckyHandler):
    def get(self):
        action = self.request.GET["action"]
        if action == generate_cse_action_name:
            generate_cse(self.request, self.response)
        elif action == oembed_consume_action_name:
            oembed_consume(self.request, self.response)
        else:
            raise BuckyHttpError, ("400", "Action not supported")

#### Custom search engines
generate_cse_action_name = "generate_cse"

def cse_url(pattern, name):
    """Return a link that will yield a custom search engine XML spec
    that only searches pages with that pattern.  This link is served
    by `generate_cse`."""
    return buckybase_hostname + "/sys?action=generate_cse&pattern=" + urlenc(pattern) + "&name=" + urlenc(name)

def generate_cse(request, response):
    tmpl_env = request.GET
    response.headers["Content-type"] = "text/xml"
    path = os.path.join(os.path.dirname(__file__), "tmpl/cse.html")
    response.out.write(template.render(path, tmpl_env))

#### oEmbed

oembed_image_width = 500
oembed_image_height = 350
oembed_image_ratio = float(oembed_image_width) / float(oembed_image_height)
oembed_image_frame_width = oembed_image_width
oembed_image_frame_height = oembed_image_height + 15 # for text below image

def oembed_consume_frame(url):
    """Called with a line that begins with http: or so."""
    for name, scheme, endpoint in oembed_providers:
        if re.match(scheme, url):
            return '<iframe width=%d height=%d frameborder=0 marginheight=0 marginwidth=0 scrolling=no src="/sys?action=oembed_consume&url=%s"></iframe>' % (oembed_image_frame_width, oembed_image_frame_height, cgi.escape(urlenc(url)))
    esc_url = cgi.escape(url)
    return '<a href="%s">%s</a>' % (esc_url, esc_url)

oembed_consume_action_name = "oembed_consume"
oembed_providers = [
    ("Flickr",
     r"^http://.*\.flickr\.com/.*$",
     "http://www.flickr.com/services/oembed/"),
    ("oohEmbed",
     r"^http://.*\.amazon\.(com|co\.uk|de|ca|jp)/.*/(gp/product|o/ASIN|obidos/ASIN|dp)/.*$",
     "http://oohembed.com/oohembed/")
    ]

def oembed_consume(request, response):
    url = request.GET["url"]
    for name, scheme, endpoint in oembed_providers:
        if re.match(scheme, url):
            result = oembed_fetch(name, endpoint, url)
            if request.GET.has_key("oembed_debug"):
                response.out.write(result)
                return
            if result:
                result_dict = simplejson.loads(result)
                result_dict["bucky_url"] = url
                result_dict["bucky_size"] = oembed_image_size(result_dict)
                response.headers["Cache-control"] = "max-age=3600"
                path = os.path.join(os.path.dirname(__file__), "tmpl/oembed_image.html")
                response.out.write(template.render(path, result_dict))
            else:
                response.out.write("oEmbed FAIL")
            return

memcache_key_maxsize = 250

def oembed_fetch(name, endpoint, url):
    memcache_key = "oe " + name + " " + url
    if len(memcache_key) <= memcache_key_maxsize:
        result = memcache.get(memcache_key)
        if result:
            return result
        else:
            result = oembed_remote_fetch(endpoint, url)
            if result:
                memcache.set(memcache_key, result, time=60*60)
                return result
            else:
                return None
    else:
        return oembed_remote_fetch(endpoint, url)

def oembed_remote_fetch(endpoint, url):
    result = urlfetch.fetch(endpoint + "?format=json&url=" + urlenc(url))
    if result.status_code == 200:
        return result.content
    else:
        return None

def oembed_image_size(result_dict):
    """Adjust image proportions so that no scrollbars are needed (most of the time)."""
    height = int(result_dict["height"])
    width = int(result_dict["width"])
    if width > (oembed_image_ratio * height): # not sure...
        # Panoramas.  Scale them full width, text will always fit below.
        return 'width="100%"'
    else:
        # Most pictures.  Scale them to almost full height, but so that text still fits below.
        return 'height="92%"'

#### Tests

def test_tag_parsing():
    assert not re.match(tag_re, "")
    assert re.match(tag_re, "foo: bar")
    assert re.match(tag_re, "foo:bar")
    assert re.match(tag_re, "foo quux: bar")
    assert re.match(tag_re, "foo quux:bar")
    assert re.match(tag_re, "foo quux: bar, fly")
    assert re.match(tag_re, "foo quux:bar, yeah, yeah")
    assert not re.match(tag_re, ": bla: bla")
    assert not re.match(tag_re, ":")
    assert not re.match(tag_re, " ")

    assert line_tag("foo: bar") == ("foo", ["bar"])
    assert line_tag("foo: bar, quux, fly") == ("foo", ["bar", "quux", "fly"])
    assert line_tag("foo:bar") == ("foo", ["bar"])
    assert line_tag("foo:bar,quux,fly") == ("foo", ["bar", "quux", "fly"])
    assert line_tag("foo quux: bar") == ("foo quux", ["bar"])

    assert {"foo": ["bar", "bar", "zippy"], "quux": ["yeehaa", "bar"] } == text_tags("""foo: bar
quux: yeehaa, bar
foo: bar
foo: zippy

bla bla""")
    assert {} == text_tags("")
    assert { "foo": ["bar"] } == text_tags("foo:bar")

def test_backlinks():
    tags = text_tags("""foo: bar
quux: yeehaa, bar
foo: noodle, bar
blam blam no tag here""")
    backlinks = tags_backlinks(tags)
    assert backlinks == { "bar": set(["foo", "quux"]),
                          "yeehaa": set(["quux"]),
                          "noodle": set(["foo"]) }
    assert tags_backlinks({}) == {}

def test_backlink_difference():

    a = { "bar": set(["foo", "quux"]),
          "yeehaa": set(["quux"]),
          "noodle": set(["foo"]) }
    b = { "bar": set(["foo", "quux"]) }

    diff = backlink_difference(a, b)
    assert diff == { "yeehaa": set(["quux"]),
                     "noodle": set(["foo"]) }

    b = { "bar": set(["foo"]),
          "yeehaa": set(["quux"]) }
    diff = backlink_difference(a, b)
    assert diff == { "bar": set(["quux"]),
                     "noodle": set(["foo"]) }

#### Run

test_tag_parsing()
test_backlinks()
test_backlink_difference()

db.run_in_transaction(setup_secret_tx)

if __name__ == "__main__":
    main()
