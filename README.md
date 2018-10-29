# backdoor
A backdoor implementation in java.
Inspired from [this project](https://github.com/jeffreysasaki/backdoor/ "jeffreysasaki/backdoor").

**Ensa Al-Hoceima**

*December 20, 2017*

# Table of Contents
* [Introduction](#introduction)
* [Requirements](#requirements)
* [Implementation](#implementation)
* [Usage](#usage)
* [Pseudocode](#pseudocode)
* [Testing](#testing)
* [Conclusion](#conclusion)


## Introduction
A backdoor is perceived as a negative vulnerability because it allows an attacker to obtain access to a
victim’s machine without proper credentials. However, a backdoor is more than just a tool of
exploitation, it is used far more commonly than one may think.
Generally speaking, the purpose of a backdoor is to allow access to a machine, implemented into the
program by the programmer. This is without a doubt a security flaw, however, it is also a tool used for
debugging and analytical purposes.
This assignment demonstrates a backdoor program where the attacker is capable of executing shell
commands on the victim’s machine and returns the response to the attacker.

## Requirements
* Application must ensure that it only receives (authenticate) those packets that are meant for the
  backdoor itself.
* The backdoor must interpret commands sent to it, execute them and send the results back.
* Incorporate an encryption scheme into the backdoor.
* Add support for multiple connections to server.

## Implementation
The program is written in java. There are two programs included in this assignment:
1. **Client.java** (Attacker)
2. **Server.java** (Backdoor Victim)

The client (attacker) program establishes a connection to the server (Victim) and will be able to execute
Linux commands against the victim’s machine. The messages will be encrypted using the AES encryption
scheme while sending data to the server. When the victim sends the message back to the client, it will
be encrypted once again; hence, the message will be decrypted to plaintext.

The server (victim) will acquire the encrypted data, decrypt it and execute the command. The command
will not appear on the victim’s message to emulate a hidden backdoor. The server then encrypts that
data, again with AES, and transmit the data back to the client.

## Usage

If you are building from source, first compile the java code. (java compiler needed)

Prior to running the program, the user must have java runtime installed

Victim: 
```
$ java Server <port> &
```
Attacker:
```
$ java Client <server_ip> <port>
```
The ampersand (&) will denote that the backdoor will be executed in the background.

## Pseudocode

**Client.java**

* Parse command-line argument
* Connect to server
* While client is connected to the server
  * Input command
  * Encrypt and Send command
  * Decrypt Response

**Server.java**

* Parse command-line argument
* While Server is up
  * Listen for connection
  * While client is connected to the server
    * Listen for client’s Input
    * Decrypt message and execute command
    * Send command’s response to client

## Testing

![alt text](https://github.com/salah3x/backdoor/raw/master/images/demo_localhost.png "Demo on localhost")

![alt text](https://github.com/salah3x/backdoor/raw/master/images/before_encrypt.png "Communication before using encryption")

![alt text](https://github.com/salah3x/backdoor/raw/master/images/after_encrypt.png "Communication after using encryption")

## Conclusion

The backdoor implementation only tested on Linux. With further enhancements to the
program, it is capable of backdooring other operating systems. In addition to that, the “exit” command
was implemented into both the client and server program. That confirms that the backdoor program is
capable of much more powerful exploitation techniques, such as screenshotting, file transfer, data
sniffing, and other malicious activities to the victim’s machine. It is important to note that this is only the
basics of a backdoor, where it executes basic commands of a backdoor program.
