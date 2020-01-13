#For this file, the majority of the code that we added can be found in the
#do_login function (any other additions were just import statements). We used
#the hash_pbkdf2 and hash_sha256 functions from hash.py to peform our salts
#and hashes.

from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
)

from app.scripts.breaches import load_breaches
from app.models.breaches import get_breaches
from app.util.hash import hash_pbkdf2, hash_sha256

@get('/login')
def login():
    return template('login')

@post('/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    error = None
    user = get_user(db, username)
    print(user)

    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)

        #for this elif statement, we change password to be the hashed/salted
        #version of the plain text password. We do this by using the hash_pbkdf2
        #function from hash.py using the plain text password and the
        #random_salt assigned to the user. This allows us to throw an error
        #if the hash of the password used to login does not match the hash of
        #the password used to register.
        elif user.password != hash_pbkdf2(password, user.random_salt):
            response.status = 401
            error = "Wrong password for {}.".format(username)
        else:
            pass  # Successful login

    elif (request.forms.get("register")):
        if user is not None:
            response.status = 401
            error = "{} is already taken.".format(username)

        #Within this block of code, we first load in the breaches. Then we have
        #several if statements -- the first checks if the username trying to log
        #in is in the plain text breach. If it is, it checks if the entered
        #password matches the password in the breach -- if it does, it blocks
        #the registration and throws an error. If it does not, no error is
        #thrown and the next if statement is checked. The same process is
        #repeated for the next two if statements (one for the hashed breach and
        #one for the salted breach). All 3 of these if statements will be
        #executed -- this accounts for cases where a username might be present
        #in more than 1 of the breaches. If no errors are thrown, the username
        #and password are approved/created.
        #To test, we took a username from the plain text breach and tested it
        #with the password from the breach -- it was rejected. When we tested
        #with a random password, it was approved. We did the same for the
        #hashed breach by converting one of the hashes into a plain text
        #password -- same results. We also did the same thing for the salted
        #breach, using the password we outputed in brute.py -- same results.
        #This confirmed that our system catches dangerous pairs from all
        #breaches.  
        else:
            load_breaches(db)
            breaches = get_breaches(db, username)

            if len(breaches[0]) != 0:
                if password == breaches[0][0].password:
                    response.status = 401
                    error = "This is a dangerous username-password pair. Please choose a different password for {}".format(username)
            if len(breaches[1]) != 0:
                pw_hash = hash_sha256(password)
                if pw_hash == breaches[1][0].hashed_password:
                    response.status = 401
                    error = "This is a dangerous username-password pair. Please choose a different password for {}".format(username)
            if len(breaches[2]) != 0:
                pw_salt = hash_pbkdf2(password, breaches[2][0].salt)
                if pw_salt == breaches[2][0].salted_password:
                    response.status = 401
                    error = "This is a dangerous username-password pair. Please choose a different password for {}".format(username)
            if error == None:
                create_user(db, username, password)

    else:
        response.status = 400
        error = "Submission error."

    if error is None:  # Perform login
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", str(session.get_id()))
        return redirect("/{}".format(username))
    return template("login", error=error)

@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")
