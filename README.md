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

link: http://natas7.natas.labs.overthewire.org
user: natas7
passw:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9




