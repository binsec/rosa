# Setting up the environment

Fuzzing itself presents
[various dangers and pitfalls](https://aflplus.plus/docs/fuzzing_in_depth/#0-common-sense-risks);
for this reason, it is recommended to run AFL++ (and thus ROSA) in a Docker container. There is an
existing ROSA container that you can use, which comes with ROSA and AFL++ preinstalled:

```console
{host} $ docker pull plumtrie/rosa:latest
```

Since ROSA and AFL++ together can create a lot of data (up to tens of gigabytes for a 24-hour run),
and because all data in the container is lost when the container is killed by default, we recommend
creating a temporary directory and mounting it as a volume in the container itself (e.g.,
`$HOME/rosa-experiment`):

```console
{host}      $ docker run -ti --rm -p 4000:4000 \
                         -v $HOME/rosa-experiment:/root/rosa-experiment plumtrie/rosa:latest
{container} $ cd /root/rosa-experiment/
```
