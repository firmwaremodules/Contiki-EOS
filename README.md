# Contiki-EOS
EOS blockchain module for Contiki-NG OS

## Structure

### Big Picture

The big picture looks like this.  On each device, we'd like to have a local lightweight nodeos module running as a Contiki process.  The device application firmware communicates to the nodeos module - submitting sensor data, polling for updates, etc.  It sort of sits at the top layer of the network stack. The nodeos module creates signed actions, queues and submits them to the broader EOS network. The nodeos module also maintains relevant network state such as the peer list and chain state data for forming valid transactions. 

Now, the local nodeos module won't look anything like that which exists today - it is something designed from the ground up for resource constrained IoT.  It communicates not over HTTP/TCP but over CoAP/UDP and it uses not JSON but a serialized binary representation.  This means that other nodeos peers must also have such a CoAP/UDP binary endpoint enabled.  So, a nodeos plugin to support this ecosystem must be developed and deployed and incorporated by a number of EOS nodes fairly close the core, if not the core itself.  Perhaps the entire network switches away from HTTP/TCP to adopt this IoT-focused architecture.

### First Steps

The first thing we need to do is create wallet and install an EOS-compatible signing engine into the Contiki framework.

#### Wallet

Many people think a cryptocurrency wallet stores their tokens. Contrary to popular belief, tokens are stored on the blockchain itself, visible to anyone and everyone.  So what's in the wallet?  The wallet stores your ability to spend those tokens.  In EOS and other blockchains (like Bitcoin), this ability is provided by the "secret key".  In EOS specifically, the power to move and allocate tokens is given by having control of these three pieces of information:
* Private key
* Corresponding public key
* Corresponding account name

In EOS, the private key is 256 bits (32 bytes), The public compressed-format key is 33 bytes, and the account name is generally 12 characters.  The device's wallet then need only contain this information, which could be provisioned specifically for that device.


