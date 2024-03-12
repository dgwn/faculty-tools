import logging
from logging import Formatter, INFO
from urllib.parse import urlparse
import json
import functools
import os
import sys
import time

from canvasapi.exceptions import CanvasException
from flask import (
    Flask,
    render_template,
    session,
    request,
    redirect,
    url_for,
    Response,
    send_from_directory,
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_caching import Cache
from sqlalchemy import text
import jinja2

# from pylti.flask import lti

from pylti1p3.contrib.flask import (
    FlaskCacheDataStorage,
    FlaskMessageLaunch,
    FlaskOIDCLogin,
    FlaskRequest,
)
from pylti1p3.deep_link_resource import DeepLinkResource
from pylti1p3.tool_config import ToolConfDict

import requests
from requests.exceptions import HTTPError

from utils import filter_tool_list, slugify

from cli import register_cli

app = Flask(__name__)
app.config.from_object(os.environ.get("CONFIG", "config.DevelopmentConfig"))
app.secret_key = app.config["SECRET_KEY"]

cache = Cache(app, config={"CACHE_TYPE": "simple"})
db = SQLAlchemy(app)
migrate = Migrate(app, db)
register_cli(app)


def select_theme_dirs():
    """
    Load theme templates, if applicable
    """
    if app.config["THEME_DIR"]:
        return ["themes/" + app.config["THEME_DIR"] + "/templates", "templates"]
    else:
        return ["templates"]


theme_dirs = select_theme_dirs()
app.jinja_loader = jinja2.ChoiceLoader([jinja2.FileSystemLoader(theme_dirs)])

# Logging
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(INFO)
handler.setFormatter(
    Formatter(
        "%(asctime)s %(levelname)s: %(message)s "
        "[in %(pathname)s: %(lineno)d of %(funcName)s]"
    )
)
app.logger.addHandler(handler)


# ============================================
# DB Models
# ============================================
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=True)
    refresh_key = db.Column(db.String(255))
    expires_in = db.Column(db.BigInteger)
    api_key = db.Column(db.String(255))

    def __init__(self, user_id, refresh_key, expires_in, api_key):
        self.user_id = user_id
        self.refresh_key = refresh_key
        self.expires_in = expires_in
        self.api_key = api_key

    def __repr__(self):
        return "<User %r>" % self.user_id


class Key(db.Model):
    __tablename__ = "key"
    id = db.Column(db.Integer, primary_key=True)
    key_set_id = db.Column(db.Integer, db.ForeignKey("key_set.id"), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    alg = db.Column(db.Text, nullable=False)  # defaults to RS256


class KeySet(db.Model):
    __tablename__ = "key_set"
    id = db.Column(db.Integer, primary_key=True)
    registrations = db.relationship("Registration", backref="key_set", lazy=True)
    keys = db.relationship("Key", backref="key_set", lazy=True)


class Registration(db.Model):
    __tablename__ = "registration"
    id = db.Column(db.Integer, primary_key=True)
    issuer = db.Column(db.String(255), nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    platform_login_auth_endpoint = db.Column(db.String(255), nullable=False)
    platform_service_auth_endpoint = db.Column(db.String(255), nullable=False)
    platform_jwks_endpoint = db.Column(db.String(255), nullable=False)
    key_set_id = db.Column(db.Integer, db.ForeignKey("key_set.id"), nullable=False)
    deployments = db.relationship("Deployment", backref="registration", lazy=True)
    __table_args__ = (db.UniqueConstraint("issuer", "client_id"),)


class Deployment(db.Model):
    __tablename__ = "deployment"
    id = db.Column(db.Integer, primary_key=True)
    deployment_id = db.Column(db.String(255), nullable=False)
    registration_id = db.Column(
        db.Integer, db.ForeignKey("registration.id"), nullable=False
    )


# ============================================
# Utility Functions
# ============================================
@app.context_processor
def ga_utility_processor():
    def google_analytics():
        return app.config["GOOGLE_ANALYTICS"]

    return dict(google_analytics=google_analytics())


@app.context_processor
def title_utility_processor():
    def title():
        return app.config["TOOL_TITLE"]

    return dict(title=title())


@app.context_processor
def theme_static_files_processor():
    def theme_static_files(folder):
        if not app.config["THEME_DIR"]:
            return list()

        try:
            all_files = os.listdir(
                "themes/{theme_dir}/static/{folder}".format(
                    theme_dir=app.config["THEME_DIR"], folder=folder
                )
            )

            css_files = list()
            for file in all_files:
                if file.endswith(".{folder}".format(folder=folder)):
                    css_files.append(file)
        except OSError:
            return list()

        return css_files

    return {
        "theme_static_css": theme_static_files("css"),
        "theme_static_js": theme_static_files("js"),
    }


@app.template_filter("slugify")
def _slugify(string):
    if not string:
        return ""
    return slugify(string)


def get_lti_config():
    registrations = Registration.query.all()

    from collections import defaultdict

    settings = defaultdict(list)
    for registration in registrations:
        settings[registration.issuer].append(
            {
                "client_id": registration.client_id,
                "auth_login_url": registration.platform_login_auth_endpoint,
                "auth_token_url": registration.platform_service_auth_endpoint,
                "auth_audience": "null",  # TODO: figure out what this is for?
                "key_set_url": registration.platform_jwks_endpoint,
                "key_set": None,
                "deployment_ids": [d.deployment_id for d in registration.deployments],
            }
        )

    # TODO: figure out more elegant way to set public/private keys without double loop
    tool_conf = ToolConfDict(settings)
    for registration in registrations:
        # Currently pylti1.3 only allows one key per client id. For now just set first one.
        key = registration.key_set.keys[0]
        tool_conf.set_private_key(
            registration.issuer,
            # ensure type is string not bytes (varies based on DB type)
            (
                key.private_key
                if isinstance(key.private_key, str)
                else key.private_key.decode("utf-8")
            ),
            client_id=registration.client_id,
        )
        tool_conf.set_public_key(
            registration.issuer,
            # ensure type is string not bytes (varies based on DB type)
            (
                key.public_key
                if isinstance(key.public_key, str)
                else key.public_key.decode("utf-8")
            ),
            client_id=registration.client_id,
        )
    return tool_conf


def return_error(msg):
    return render_template("error.html", msg=msg)


# for the pylti decorator
# def error(exception=None):
#     app.logger.error("PyLTI error: {}".format(exception))
#     return return_error(
#         (
#             "Authentication error, please refresh and try again. If this error "
#             "persists, please contact support."
#         )
#     )


@app.route("/themes/static/<path:filename>")
def theme_static(filename):  # pragma: nocover
    static_dir = "themes/{theme_dir}/static".format(theme_dir=app.config["THEME_DIR"])
    return send_from_directory(static_dir, filename)


# ============================================
# LTI 1.3
# ============================================
def get_launch_data_storage():
    return FlaskCacheDataStorage(cache)


def lti_required(role=None):
    """
    LTI Protector - only allow access to routes if user has been authenticated and has a launch ID.
    You can also pass in a role to restrict access to certain roles e.g. @lti_required(role="staff")

    Args:
        role (str, optional): The role to restrict access to. Defaults to None.

    Returns:
        function: The decorated function.
    """

    def decorator(func):
        @functools.wraps(func)
        def secure_function(*args, **kwargs):
            if "launch_id" not in session:
                return (
                    "<h2>Unauthorized</h2><p>You must use this tool in an LTI context.</p>",
                    401,
                )

            if role == "staff":
                if "roles" not in session or (
                    "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator"
                    not in session["roles"]
                    and "http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator"
                    not in session["roles"]
                    and "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"
                    not in session["roles"]
                ):
                    return (
                        "<h2>Unauthorized</h2><p>You must be faculty to use this tool.</p>",
                        401,
                    )

            return func(*args, **kwargs)

        return secure_function

    return decorator


@app.route("/login/", methods=["GET", "POST"])
def login():
    tool_conf = get_lti_config()

    launch_data_storage = get_launch_data_storage()

    flask_request = FlaskRequest()

    target_link_uri = flask_request.get_param("target_link_uri")
    if not target_link_uri:
        raise Exception('Missing "target_link_uri" param')

    oidc_login = FlaskOIDCLogin(
        flask_request, tool_conf, launch_data_storage=launch_data_storage
    )
    return oidc_login.enable_check_cookies(
        main_msg="Your browser prohibits saving cookies in an iframe.",
        click_msg="Click here to open the application in a new tab.",
    ).redirect(target_link_uri)


@app.route("/launch/", methods=["POST"])
def launch():
    tool_conf = get_lti_config()

    flask_request = FlaskRequest()
    launch_data_storage = get_launch_data_storage()
    message_launch = FlaskMessageLaunch(
        flask_request, tool_conf, launch_data_storage=launch_data_storage
    )
    session["launch_id"] = message_launch.get_launch_id()
    session["course_id"] = message_launch.get_launch_data()[
        "https://purl.imsglobal.org/spec/lti/claim/custom"
    ]["canvas_course_id"]
    session["canvas_user_id"] = message_launch.get_launch_data()[
        "https://purl.imsglobal.org/spec/lti/claim/custom"
    ]["canvas_user_id"]
    session["roles"] = message_launch.get_launch_data()[
        "https://purl.imsglobal.org/spec/lti/claim/roles"
    ]
    session["error"] = False

    # redirect to the oauth flow
    return redirect(url_for("auth"))


@app.route("/jwks/", methods=["GET"])
def get_jwks():
    return get_lti_config().get_jwks()


# ============================================
# Web Views / Routes
# ============================================


@app.route("/")
@lti_required(role="staff")
# @lti(error=error, role="staff", app=app)
def index():
    """
    Main entry point to web application, get all whitelisted LTIs and send the data to the template
    """
    user = Users.query.filter_by(user_id=int(session["canvas_user_id"])).first()
    api_key = user.api_key
    if api_key is None:
        app.logger.error("api_key not set")
        return return_error(
            (
                "Authentication error: missing API key. Please refresh and try again."
                "If this error persists, please contact support."
            )
        )

    # Test API key to see if they need to reauthenticate
    auth_header = {"Authorization": "Bearer " + api_key}
    r = requests.get(app.config["API_URL"] + "users/self", headers=auth_header)
    if "WWW-Authenticate" in r.headers:
        # reroll oauth
        app.logger.info(
            (
                "WWW-Authenticate found in headers, or status code was 401. "
                "Re-rolling oauth.\n {0} \n {1} \n {2}"
            ).format(r.status_code, r.headers, r.url)
        )

        return redirect(
            app.config["BASE_URL"]
            + "login/oauth2/auth?client_id="
            + app.config["OAUTH2_ID"]
            + "&response_type=code&redirect_uri="
            + app.config["OAUTH2_URI"]
        )

    if "WWW-Authenticate" not in r.headers and r.status_code == 401:
        # not authorized
        app.logger.warning("Not an Admin. Not allowed.")
        return return_error(
            (
                "You are not enrolled in this course as a Teacher or Designer. "
                "If this error persists, please contact support."
            )
        )

    if r.status_code == 404:
        # something is wrong with the key! It can't get user out of the API key
        app.logger.error(
            (
                "404 in checking the user's api key. Request info:\n"
                "User ID: {0} Course: {1} \n {2} \n Request headers: {3} \n {4}"
            ).format(
                session["canvas_user_id"],
                session["course_id"],
                r.url,
                r.headers,
                r.json(),
            )
        )
        return redirect(
            app.config["BASE_URL"]
            + "login/oauth2/auth?client_id="
            + app.config["OAUTH2_ID"]
            + "&response_type=code&redirect_uri="
            + app.config["OAUTH2_URI"]
        )

    r = requests.get(
        app.config["API_URL"]
        + "courses/{0}/external_tools?include_parents=true&per_page=100".format(
            session["course_id"]
        ),
        headers=auth_header,
    )

    try:
        tools_by_category, category_order = filter_tool_list(
            session["course_id"], api_key
        )
    except CanvasException:
        app.logger.exception("Couldn't connect to Canvas")
        return return_error(
            (
                "Couldn't connect to Canvas, please refresh and try again. "
                "If this error persists please contact support."
            )
        )
    except (ValueError, IOError):
        msg = "There is something wrong with the whitelist.json file"
        app.logger.exception(msg)
        return return_error(msg)

    return render_template(
        "main_template.html",
        tools_by_category=tools_by_category,
        category_order=category_order,
        course=session["course_id"],
    )


@app.route("/status", methods=["GET"])
def status():
    """
    Runs smoke tests and reports status
    """

    status = {
        "tool": "Faculty Tools",
        "checks": {"index": False, "xml": False, "db": False, "dev_key": False},
        "url": url_for("index", _external=True),
        "xml_url": url_for("xml", _external=True),
        "base_url": app.config["BASE_URL"],
        "debug": app.debug,
    }

    # Check index
    try:
        response = requests.get(url_for("index", _external=True), verify=False)
        index_check = (
            response.status_code == 200 and app.config["TOOL_TITLE"] in response.text
        )
        status["checks"]["index"] = index_check
    except Exception:
        app.logger.exception("Index check failed.")

    # Check xml
    try:
        response = requests.get(url_for("xml", _external=True), verify=False)
        status["checks"]["xml"] = "application/xml" in response.headers.get(
            "Content-Type"
        )
    except Exception:
        app.logger.exception("XML check failed.")

    # Check DB connection
    try:
        db.session.query(text("1")).all()
        status["checks"]["db"] = True
    except Exception:
        app.logger.exception("DB connection failed.")

    # Check dev key?
    try:
        response = requests.get(
            "{}login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}".format(
                app.config["BASE_URL"],
                app.config["OAUTH2_ID"],
                app.config["OAUTH2_URI"],
            )
        )
        status["checks"]["dev_key"] = response.status_code == 200
    except Exception:
        app.logger.exception("Dev Key check failed.")

    # Overall health check - if all checks are True
    status["healthy"] = all(v is True for k, v in list(status["checks"].items()))
    return Response(json.dumps(status), mimetype="application/json")


@app.route("/xml/", methods=["POST", "GET"])
def xml():
    """
    Returns the lti.xml file for the app.
    XML can be built at https://www.eduappcenter.com/
    """
    return Response(
        render_template("test.xml", url=request.url_root), mimetype="application/xml"
    )


@app.route("/lticonfig/", methods=["GET"])
def config():
    domain = urlparse(request.url_root).netloc
    return Response(
        render_template(
            "lti.json",
            domain=domain,
            url_scheme=app.config["PREFERRED_URL_SCHEME"],
        ),
        mimetype="application/json",
    )


# OAuth login
# Redirect URI
@app.route("/oauthlogin", methods=["POST", "GET"])
@lti_required(role="staff")
# @lti(error=error, request="session", role="staff", app=app)
def oauth_login():

    code = request.args.get("code")

    if code is None:
        app.logger.warning("No `code` response from Canvas. User probaly hit 'Cancel'.")
        return return_error(
            (
                "Authentication error, please refresh and try again. If this error "
                "persists, please contact support."
            )
        )

    payload = {
        "grant_type": "authorization_code",
        "client_id": app.config["OAUTH2_ID"],
        "redirect_uri": app.config["OAUTH2_URI"],
        "client_secret": app.config["OAUTH2_KEY"],
        "code": code,
    }
    r = requests.post(app.config["BASE_URL"] + "login/oauth2/token", data=payload)

    try:
        r.raise_for_status()
    except HTTPError:
        app.logger.exception("Error status from oauth, authentication error")

        return return_error(
            (
                "Authentication error, please refresh and try again. If this error "
                "persists, please contact support."
            )
        )

    if "access_token" in r.json():
        api_key = r.json()["access_token"]
        refresh_token = r.json()["refresh_token"]

        if "expires_in" in r.json():
            # expires in seconds
            # add the seconds to current time for expiration time
            current_time = int(time.time())
            expires_in = current_time + r.json()["expires_in"]
            session["expires_in"] = expires_in

            # check if user is in the db
            user = Users.query.filter_by(user_id=int(session["canvas_user_id"])).first()
            if user is not None:
                try:
                    # update the current user's expiration time in db
                    user.refresh_key = refresh_token
                    user.expires_in = session["expires_in"]
                    user.api_key = api_key
                    db.session.add(user)
                    db.session.commit()
                except Exception:
                    app.logger.exception(
                        "Error in updating user's expiration time in the db:\n {}".format(
                            session
                        )
                    )
                    return return_error(
                        "Authentication error, please refresh and try again. "
                        "If this error persists, please contact support."
                    )

                return redirect(url_for("index"))
            else:
                try:
                    # add new user to db
                    new_user = Users(
                        session["canvas_user_id"],
                        refresh_token,
                        session["expires_in"],
                        api_key,
                    )
                    db.session.add(new_user)
                    db.session.commit()
                except Exception:
                    # Error in adding user to the DB
                    app.logger.exception(
                        "Error in adding user to db: \n {}".format(session)
                    )
                    return return_error(
                        (
                            "Authentication error, please refresh and try again. "
                            "If this error persists, please contact support."
                        )
                    )

                return redirect(url_for("index"))

    app.logger.warning(
        (
            "Error with checking access_token in r.json() block\n"
            "User: {0} Course: {1} \n {2} \n Request headers: {3} \n r.json(): {4}"
        ).format(
            session["canvas_user_id"], session["course_id"], r.url, r.headers, r.json()
        )
    )
    return return_error(
        (
            "Authentication error, please refresh and try again. If this error "
            "persists, please contact support."
        )
    )


def refresh_access_token(user):
    """
    Use a user's refresh token to get a new access token.

    :rtype: dict
    :returns: Dictionary with keys 'access_token' and 'expiration_date'.
        Values will be `None` if refresh fails.
    """
    refresh_token = user.refresh_key

    payload = {
        "grant_type": "refresh_token",
        "client_id": app.config["OAUTH2_ID"],
        "redirect_uri": app.config["OAUTH2_URI"],
        "client_secret": app.config["OAUTH2_KEY"],
        "refresh_token": refresh_token,
    }
    response = requests.post(
        app.config["BASE_URL"] + "login/oauth2/token", data=payload
    )

    try:
        response.raise_for_status()
    except HTTPError:
        app.logger.exception("Failed refresh. Probably bad refresh token.")
        return {"access_token": None, "expiration_date": None}

    try:
        response_json = response.json()
    except ValueError:
        app.logger.exception(
            "Unable to load JSON response of refresh. Possibly bad refresh token."
        )
        return {"access_token": None, "expiration_date": None}

    if "access_token" not in response_json:
        app.logger.warning(
            (
                "Access token not in json. Bad api key or refresh token.\n"
                "URL: {}\n"
                "Status Code: {}\n"
                "Payload: {}\n"
                "Session: {}"
            ).format(response.url, response.status_code, payload, session)
        )
        return {"access_token": None, "expiration_date": None}

    api_key = response_json["access_token"]
    app.logger.info("New access token created\n User: {0}".format(user.user_id))

    if "expires_in" not in response_json:
        app.logger.warning(
            (
                "expires_in not in json. Bad api key or refresh token.\n"
                "URL: {}\n"
                "Status Code: {}\n"
                "Payload: {}\n"
                "Session: {}"
            ).format(response.url, response.status_code, payload, session)
        )
        return {"access_token": None, "expiration_date": None}

    current_time = int(time.time())
    new_expiration_date = current_time + response_json["expires_in"]

    try:
        # Update expiration date in db
        user.expires_in = new_expiration_date
        db.session.commit()
    except Exception:
        readable_expires_in = time.strftime(
            "%a, %d %b %Y %H:%M:%S", time.localtime(user.expires_in)
        )
        readable_new_expiration = time.strftime(
            "%a, %d %b %Y %H:%M:%S", time.localtime(new_expiration_date)
        )
        app.logger.error(
            (
                "Error in updating user's expiration time in the db:\n"
                "session: {}\n"
                "DB expires_in: {}\n"
                "new_expiration_date: {}"
            ).format(session, readable_expires_in, readable_new_expiration)
        )
        return {"access_token": None, "expiration_date": None}

    return {"access_token": api_key, "expiration_date": new_expiration_date}


# Checking the user in the db
@app.route("/auth", methods=["POST", "GET"])
@lti_required(role="staff")
# @lti(error=error, request="initial", role="staff", app=app)
def auth():

    # Try to grab the user
    user = Users.query.filter_by(user_id=int(session["canvas_user_id"])).first()

    if not user:
        # not in db, go go oauth!!
        app.logger.info(
            "Person doesn't have an entry in db, redirecting to oauth: {0}".format(
                session["canvas_user_id"]
            )
        )
        return redirect(
            app.config["BASE_URL"]
            + "login/oauth2/auth?client_id="
            + app.config["OAUTH2_ID"]
            + "&response_type=code&redirect_uri="
            + app.config["OAUTH2_URI"]
        )

    # Get the expiration date
    expiration_date = user.expires_in

    # If expired or no api_key
    if int(time.time()) > expiration_date or not user.api_key:
        readable_time = time.strftime(
            "%a, %d %b %Y %H:%M:%S", time.localtime(user.expires_in)
        )
        app.logger.info(
            (
                "Expired refresh token or api_key not in session\n User: {0} \n "
                "Expiration date in db: {1} Readable expires_in: {2}"
            ).format(user.user_id, user.expires_in, readable_time)
        )

        refresh = refresh_access_token(user)

        if refresh["access_token"] and refresh["expiration_date"]:
            user.api_key = refresh["access_token"]
            session["expires_in"] = refresh["expiration_date"]
            return redirect(url_for("index"))
        else:
            # Refresh didn't work. Reauthenticate.
            app.logger.info("Reauthenticating:\nSession: {}".format(session))
            return redirect(
                app.config["BASE_URL"]
                + "login/oauth2/auth?client_id="
                + app.config["OAUTH2_ID"]
                + "&response_type=code&redirect_uri="
                + app.config["OAUTH2_URI"]
            )
    else:
        # API key that shouldn't be expired. Test it.
        auth_header = {"Authorization": "Bearer " + user.api_key}
        r = requests.get(
            app.config["API_URL"] + "users/%s/profile" % (session["canvas_user_id"]),
            headers=auth_header,
        )
        # check for WWW-Authenticate
        # https://canvas.instructure.com/doc/api/file.oauth.html
        if "WWW-Authenticate" not in r.headers and r.status_code != 401:
            return redirect(url_for("index"))
        else:
            # Key is bad. First try to get new one using refresh
            new_token = refresh_access_token(user)["access_token"]

            if new_token:
                session["api_key"] = new_token
                return redirect(url_for("index"))
            else:
                # Refresh didn't work. Reauthenticate.
                app.logger.info("Reauthenticating\nSession: {}".format(session))
                return redirect(
                    app.config["BASE_URL"]
                    + "login/oauth2/auth?client_id="
                    + app.config["OAUTH2_ID"]
                    + "&response_type=code&redirect_uri="
                    + app.config["OAUTH2_URI"]
                )


@app.route("/get_sessionless_url/<lti_id>/<is_course_nav>")
# @lti(error=error, role="staff", app=app)
def get_sessionless_url(lti_id, is_course_nav):
    sessionless_launch_url = None

    user = Users.query.filter_by(user_id=int(session["canvas_user_id"])).first()

    if is_course_nav == "True":
        auth_header = {"Authorization": "Bearer " + user.api_key}
        # get sessionless launch url for things that come from course nav
        url = (
            "{0}courses/{1}/external_tools/sessionless_launch?id={2}"
            "&launch_type=course_navigation"
        )
        r = requests.get(
            url.format(app.config["API_URL"], session["course_id"], lti_id),
            headers=auth_header,
        )
        if r.status_code >= 400:
            app.logger.error(
                (
                    "Bad response while getting a sessionless "
                    "launch url:\n {0} {1}\n LTI: {2} \n"
                ).format(r.status_code, r.url, lti_id)
            )
            return return_error(
                (
                    "Error in a response from Canvas, please "
                    "refresh and try again. If this error persists, "
                    "please contact support."
                )
            )
        else:
            sessionless_launch_url = r.json()["url"]

    if sessionless_launch_url is None:
        auth_header = {"Authorization": "Bearer " + user.api_key}
        # get sessionless launch url
        r = requests.get(
            app.config["API_URL"]
            + "courses/{0}/external_tools/sessionless_launch?id={1}".format(
                session["course_id"], lti_id
            ),
            headers=auth_header,
        )
        if r.status_code >= 400:
            app.logger.error(
                (
                    "Bad response while getting a sessionless "
                    "launch url:\n {0} {1}\n LTI: {2} \n"
                ).format(r.status_code, r.url, lti_id)
            )
            return return_error(
                (
                    "Error in a response from Canvas, please "
                    "refresh and try again. If this error persists, "
                    "please contact support."
                )
            )
        else:
            sessionless_launch_url = r.json()["url"]

    return sessionless_launch_url
