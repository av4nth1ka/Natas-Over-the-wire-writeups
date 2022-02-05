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


