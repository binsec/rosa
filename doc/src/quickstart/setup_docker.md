# Setting up the environment

Fuzzing itself presents [various dangers and
pitfalls](https://aflplus.plus/docs/fuzzing_in_depth/#0-common-sense-risks); for this reason, it is
recommended to run AFL++ (and thus ROSA) in a Docker container. There is an existing ROSA container
that you can use, which comes with ROSA and AFL++ preinstalled:
[TODO: put final link/image name here]
```console
{host} $ docker pull XXX
```

Since ROSA and AFL++ together can create a lot of data (on the order of gigabytes for a 24-hour
run), and because all data in the container is lost when the container is killed by default, we
recommend creating a temporary directory and mounting it as a volume in the container itself (e.g.,
`$HOME/rosa-experiment`):

```console
{host}      $ docker run -ti --rm -v $HOME/rosa-experiment:/root/rosa-experiment XXX
{container} $ cd /root/rosa-experiment/
```
