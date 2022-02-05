# Natas--Over-the-wire-writeups

# level-0

link:  http://natas0.natas.labs.overthewire.org
given user: natas0
pass: natas0
When we login with the above credentials, We can see a msg: `You can find the password for the next level on this page.`
When we view the page source, we can find the password to next level.
`-The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto`

# Level 0 -> level 1

link:http://natas1.natas.labs.overthewire.org
Given user: natas1
pass:gtVrDuiDfck831PqWsLEZy5gyDz1clto
When we login with the above credentials, we can see the message `You can find the password for the next level on this page, but rightclicking has been blocked!`.
So, we will press `ctrl+u` to view the page source. There we get the password for the next level.
`The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi`

# Level 1 -> Level 2

link:http://natas2.natas.labs.overthewire.org
given user : natas2
pass: ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi
When we login witht the above credentials, we can see the message, `there is nothing on this page.`
When we view the page source we can see a file `/files/pixels.png`.
When we go to the files directory, `/files/` we can see a file named `users.txt`. In that file we can see the password of the next level.
`password: sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14`

# Level 2 -> Level 3

link: http://natas3.natas.labs.overthewire.org
given user: natas3
password: sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
When we login with the credentials, we can see the message `there is nothing on this page`.
When we the page source we can see a hint `No more information leaks!! Not even Google will find it this time...`
From this we can understand that `robots.txt` can be used. In robots.txt we can find a disallow directory  `/s3cr3t/`.
We we visit `http://natas3.natas.labs.overthewire.org/s3cr3t/`, we can see a file named `users.txt` in that directory.
Opening `users.txt` gives us the password.
`password: Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ`


