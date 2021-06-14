# Docker
Aims to add a Katzenpost catshadow test for Katzenmint. Right now, it's a integration test of Katzenmint PKI. Clone
 and see how Katzenmint PKI works.

# Test
Before running the test, you should build docker container for katzenmint-pki.

```BASH
$ cd katzenmint-pki
$ docker build --no-cache -t katzenmint/pki .
```

Then, start three katzenmint pki nodes.
```BASH
$ docker-compose up
```

Now, you can checkout information of katzenmint pki nodes with curl command.
```BASH
# node1
$ curl http://127.0.0.1:21483/net_info

# node2
$ curl http://127.0.0.1:21484/net_info

# node3
$ curl http://127.0.0.1:21485/net_info
```

# Clean up chaindata and restart

You can simply cleanup chaindata in one command.
```BASH
$ sh cleanup.sh
```

Then, restart three katzenmint pki nodes.
```BASH
$ docker-compose up
```

# TBD
Add mixes/providers into docker-compose, and make sure it works.
Add catshadow.