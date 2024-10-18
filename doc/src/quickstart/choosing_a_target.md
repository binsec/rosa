# Choosing a target program

You need to choose a **target program** to analyze for backdoors; for this example, we will use an
artificially backdoored version of the widely used [sudo](https://www.sudo.ws) program. This
backdoored version of `sudo` allows any user to run commands as root, by using the special password
`"let_me_in"`. This version of `sudo` is taken from the [TODO: add the final link to the ROSARUM
repo] [ROSARUM](todo-link) backdoor benchmark and can be found in
`/root/examples/sudo/target/backdoored/build/bin/sudo` in your container. It is also aliased to
`/usr/bin/backdoored-sudo`.

Let's actually test it out:
```console
{container} $ echo "wrong_password" | backdoored-sudo --stdin --reset-timestamp -- id
Password: Sorry, try again.
Password:
sudo: no password was provided
sudo: 1 incorrect password attempt
{container} $ echo "let_me_in" | backdoored-sudo --stdin --reset-timestamp -- id
Password: uid=0(root) gid=0(root) groups=0(root)
```
