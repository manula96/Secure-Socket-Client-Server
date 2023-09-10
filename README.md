# Task 1: Securing a Communication Channel with SSL

For this task you will set up SSL certificates with either XCA or OpenSSL, and modify the server.py
and client.py to use those certificates.


## Setup

To run the interceptor program you will need to install a recent version of python3, preferably version 3.7
or higher. You will also want to install the packages from the requirements.txt, one way to do so
is by running the following command directly in the command prompt or terminal:

```sh
pip3 install -r requirements.txt
```

To run the other programs you will only need a standard installation of the Java-OpenJDK.

Finally, you will want to have either the XCA (https://hohnstaedt.de/xca/) or
OpenSSL (https://www.openssl.org/) programs to create SSL certificates.


## Running the programs

With the setup done, you will first want to run the interceptor adversary. The interceptor performs
packet sniffing to observe packets being sent and received by the network card of the computer it
is running on. This means the program requires administrator access, so you may find that on linux
and mac systems you will need to prepend sudo to the command used to run it. The following command
runs the interceptor adversary:

```sh
python3 interceptor.py
```

The interceptor will say that it is starting interception, this means you will be read to run the
server then client. The server needs to be started first with:

```sh
java Server.java
```

It will say that is listening on a port, which means you are ready to start the client with:

```sh
java Client.java
```

The server and client will exchange messages and output what they got from eachother. You can now
check the interceptor again, it will have captured those messages and will also have said their
values. The captured messages are doubled since we are sending and receiving to the same computer,
so both sides of the communication are captured.

When you have completed the task successfully, the interceptor will instead say that the packets
are encrypted, and not say the message.
If you have troubles with getting the interceptor working, you can also validate by looking at
the packets using the wireshark tool https://www.wireshark.org/.