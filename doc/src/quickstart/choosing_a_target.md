# Choosing a target program

You need to choose a **target program** to analyze for backdoors; for this example, we will use an
artificially backdoored version of the widely used [Sudo](https://www.sudo.ws) program. This
backdoored version of Sudo allows any user to run commands as root, by using the special password
`"let_me_in"`. This version of Sudo is taken from the [ROSARUM](https://github.com/binsec/rosarum)
backdoor benchmark and can be found in `/root/rosa/examples/sudo/target/backdoored/build/bin/sudo`
in your container. It is also aliased to `/usr/bin/backdoored-sudo`.

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
