# importing siphash
import siphash

# performs the siphash
def callhash(hashkey, inval):
    return siphash.SipHash_2_4(hashkey, inval).hash()

# maps the siphash to a value in the range of the hash table size
def ht_hash(hashkey, inval, htsize):
    return callhash(hashkey, inval) % htsize

# This function should finds and outputs the colliding strings in a list
def find_collisions(key, num_collisions):
    size = 2**16 # size of the hash table
    third_size = int(size/3) # 1/3 the size of the hash table
    hash_table = [None]*size # initializing an empty array of size of hash table
    collisions = [] # empty array to store final collisions

    count = 0 # count will iterate and will be encoded as the string to be hashed
    flag = True # flag set to True to continue while loop until set to False

    # the following two variables were added due to memory issues. Since our
    # memory was running out, we added the following fix. Once a certain number
    # (in this case a third of the hash table spots, or once buckets_cap is equal
    # to third_size) of hash spots have cap_collisions values (in this case 500),
    # we only allow hash strings to be added to those spots that that already have
    # cap_collisions (500) or more. This allows us to save a lot of memory
    buckets_cap = 0
    cap_collisions = int(num_collisions/2)

    # while loop continues until a spot in the hash table has num_collisions
    # (1000) values
    while (flag):
        # take the count variable, encode it, and then hash it
        random_string = str(count).encode("utf-8")
        h_of_x = ht_hash(key, random_string, size)

        # initialize the list for this hash index with the encoded (count) string
        # so long as there are no values for this hash index and buckets_cap
        # has not reached third_size yet
        if hash_table[h_of_x] is None and buckets_cap != third_size:
            hash_table[h_of_x] = [random_string]
        else:
            # if buckets_cap has reached third_size, we need to be more careful
            # about memory use. Therefore, we only add the encoded string to the
            # list of collisions if there are already 500 or more collisions
            if buckets_cap == third_size:
                if len(hash_table[h_of_x]) >= cap_collisions:
                    hash_table[h_of_x].append(random_string)
            # in all other scenarios, just append the encoded string to the list
            # of collisions
            else: 
                hash_table[h_of_x].append(random_string)

            # every time the number of collisions in a hash index reaches 500,
            # increase buckets_cap by 1 so that we can track when 1/3 of the
            # hash indices have reached 500 or more
            if len(hash_table[h_of_x]) == cap_collisions:
                buckets_cap += 1

            # once we have a hash index with num_collisions (1000) collisions,
            # we set flag to False to break out of the loop and save those 1000
            # collisions to our collisions list
            if len(hash_table[h_of_x]) == num_collisions:
                flag = False
                collisions = hash_table[h_of_x]

        count += 1

    return collisions


# This function takes the list of collisions and verifies they all have the same
# SipHash output under the given key
def check_collisions(key, colls):
    size = 2**16
    baseline = ht_hash(key, colls[0], size) # baseline to compare to
    flag = True

    # check each collision with the baseline to make sure all Siphash to the
    # same values. If they do not, set flag to False
    for coll in colls:
        current_coll = ht_hash(key, coll, size)
        if current_coll != baseline:
            flag = False

    return flag


# main function to return 20 collisions for the listed key and verify that they
# all indeed have the same Siphash output
if __name__=='__main__':
    key = b'\x00'*16
    colls = find_collisions(key, 20)
    for i in range(len(colls)):
        print("Collision #", i+1, ": ", colls[i])
    print("check_collisions function returned: ", check_collisions(key, colls))
