import sys

from flask import Flask, render_template, request
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from passlib.context import CryptContext
from passlib import hash
from passlib.utils.binary import h64, ab64_encode, b64s_encode

app = Flask(__name__)
myctx = CryptContext(schemes=[
    "bcrypt",
    "sha256_crypt",
    "sha512_crypt",
    "unix_disabled",
    "bsd_nthash",
    "md5_crypt",
    "sha1_crypt",
    "sun_md5_crypt",
    "des_crypt",
    "bsdi_crypt",
    "argon2",
    "bcrypt_sha256",
    "phpass",
    "pbkdf2_sha1",
    "pbkdf2_sha256",
    "pbkdf2_sha512",
    "scrypt",
    "apr_md5_crypt",
    "cta_pbkdf2_sha1",
    "dlitz_pbkdf2_sha1"
])
app.jinja_env.globals.update(h64encode_int24=h64.encode_int24)
app.jinja_env.globals.update(h64encode_int6=h64.encode_int6)
app.jinja_env.globals.update(b64encode=b64s_encode)
app.jinja_env.globals.update(b64=b64encode)
app.jinja_env.globals.update(ab64_encode=ab64_encode)
app.jinja_env.globals.update(b16=lambda x: "{:x}".format(x))
app.jinja_env.globals.update(CTA_ALTCHARS=b"-_")

def get_format(pwd):
    return myctx.identify(pwd)

@app.route('/')
def hello_world():
    return render_template('home.html')

@app.route('/', methods=["POST"])
def parse_form():
    username = None
    rest = None
    pwd = request.form.get('pwd', '').strip()
    if ':' in pwd:
        username = pwd.split(':')[0]
        rest = ':'.join(pwd.split(':')[2:])
        pwd = pwd.split(':')[1]

    name = get_format(pwd)
    if not name:
        return render_template('home.html', fail='invalid line')

    scheme = {
        'name': name,
        'hash': None,
        'username': username,
        'rest': rest
    }
    try:
        hasher = getattr(sys.modules["passlib.hash"], name)
        hasher = hasher.from_string(pwd)
        scheme['hash'] = hasher
    except KeyError:
        return render_template('home.html', fail=True)
    except AttributeError as e:
        print(name, e)
        # bsd_nthash
        # unix_disabled
        return "Error", 500
    except ValueError as e:
        print('Incorrect padding' in str(e) and name == 'cta_pbkdf2_sha1', 'Incorrect padding' in str(e))
        if 'Incorrect padding' in str(e) and name == 'cta_pbkdf2_sha1':
            # There is a bug in passlib not recognizing dlitz when cta is also enabled
            hasher = getattr(sys.modules["passlib.hash"], 'dlitz_pbkdf2_sha1')
            hasher = hasher.from_string(pwd)
            scheme['name'] = 'dlitz_pbkdf2_sha1'
            scheme['hash'] = hasher
        else:
            return render_template('home.html', format=name, fail=str(e))
    return render_template('home.html', format=name, fail=False, scheme=scheme)

@app.route('/parse/<string:pwd>')
def parse_api(pwd):
    try:
        name = get_format(b64decode(pwd))
    except BinasciiError:
        return "Not a valid Base64 parameter", 500
    return '{}'.format(name)

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', code=404, error='File not found'), 404

if __name__ == "__main__":
    app.run(host='127.0.0.1')
