aws-metadata
============

A simple mock metadata service for local development.

Usage
====

```
$ sudo ifconfig lo0 alias 169.254.169.254
$ sudo python ./metadata.py metadata.json
$ curl http://169.254.169.254/latest/meta-data/instance-id
i-00000000
```

