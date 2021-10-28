import re
import hashlib
import requests



########################
# Working code in below
url='http://68.183.43.71:31906/'
try:
    # Create a session using requests.session
    establish_session = requests.session()

    # Make a request session to the URL
    session_output = establish_session.get(url)

    # To view the response from session, can use session_object.text
    # print(session_output.text)

    # Find the strings to be md5 encrypted - that will return list
    # we are using re.findall here to search for “all” occurrences
    # r = to specify regular expression
    # base on the source code, we can searching for "h3 align='center'>
    # then () is to capture the group that matches the regular expression to capture strings to be encrypted
    # last, insert the session_output.txt as the response from the request
    strings = re.findall(r'h3 align=\'center\'>(.+?\w+)</', session_output.text)

    # Generate md5 hash for the string
    md5_hash = hashlib.md5(strings[0].encode('utf-8')).hexdigest()
    # print(md5_hash)

    # Create post data
    post_data = {'hash': md5_hash}
    # print(post_data)

    # Send the post data to the session
    send_post = establish_session.post(url = url, data = post_data)
    print(send_post.text)

except KeyboardInterrupt:
    print('interrupted!')
