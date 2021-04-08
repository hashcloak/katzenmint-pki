# Docker
Aims to add a Katzenpost catshadow test for Katzenmint. Right now, it's a integration test of Katzenmint PKI. Clone
 and see how Katzenmint PKI works.

# Test
Before running the test, you should build docker container for katzenmint-pki.

```BASH
$ cd katzenmint-pki
$ docker build --no-catch -t katzenmint/pki .
```

Then, start three katzenmint pki nodes

```BASH
$ docker-compose up
```

# TBD
Add mixes/providers into docker-compose, and make sure it works.
Add catshadow.