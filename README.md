# Contiki-EOS
EOS blockchain communication module for Smart Contract Sensors powered by Contiki-NG OS.

## Why EOS
The prominent blockchain platform Ethereum suffers from two fundamental problems that prevent it from being an option for building real distributed applications:
* Scalability. Limited to on the order of 10 transactions per second, the Ethereum global network is woefully inadequate for supporting IoT deployments of any sizeable quantity, even if they're sending messages infrequently.
* Usability. Requiring each user (could be device) to spend a variable transaction fee (i.e. gas) to access network resources is counter-intuitive to some business models and imposes constraints on how dApps are architected.  Essentially the fundamental operation of your business is hostage to a global marketplace for Eth.  I suppose one can make the same argument for EOS, however there is one clear distinction. With EOS, a business can claim (stake for) the resources it needs one time only (at launch for example), then operate the business without transaction costs.

EOS is a working blockchain platform that right now solves these problems.  EOS now supports over 1000 TX per second, and fundamentally alters the access model whereby users do not need to pay to use the system.  The business (e.g. IoT platform) pays (stakes tokens) to access blockchain resources. It is up to the business to decide how to monetize their services - and they can even be free.

I suppose I should say something about IOTA, after all, it has "IOT" in its name.  Well, there is no much to say really.  Burdening the battery-powered devices themselves with the responsibility for reaching global state consense hardly seems like the right way to allocate resources.  Plus, IOTA makes no sense.  Good luck with that.

## Structure

### Big Picture

The future of IoT is now.  A global network of sensors delivering secured, auditable and permissiond data to a decentralized platform. We _can_ take on GAFAM.  Anything is possible.

The big picture begins to look like this.  On each device, we'd like to have a local lightweight nodeos module running as a Contiki process.  The local device application firmware communicates to the nodeos module - submitting sensor data, polling for updates, etc.  It sort of sits at the top layer of the network stack. The nodeos module creates signed actions, queues then submits transactions to the broader EOS network and its smart contracts. The nodeos module also maintains relevant network state such as the peer list and chain state data for forming valid transactions. 

Now, the local nodeos module won't look anything like that which exists today - it is something designed from the ground up for resource constrained IoT.  It communicates not over HTTP/TCP but over CoAP/UDP and it uses not JSON but a serialized binary representation.  This means that other nodeos peers must also have such a CoAP/UDP binary endpoint enabled.  So, a nodeos plugin to support this ecosystem must be developed and deployed and incorporated by a number of EOS nodes fairly close the core, if not the core itself.  Perhaps the entire network switches away from HTTP/TCP to adopt this IoT-focused architecture.

### First Steps

The first thing we need to do is create a wallet and install an EOS-compatible transaction signing engine into the Contiki framework.

#### Wallet

Many people think a cryptocurrency wallet stores their tokens. Contrary to popular belief, tokens are stored on the blockchain itself, visible to anyone and everyone.  So what's in the wallet?  Simply put, the wallet stores your ability to spend those tokens.  In EOS and other blockchains (like Bitcoin), this ability is provided by the "private key".  In EOS specifically, the power to move and allocate tokens is given by having control of these three pieces of information:
* Private key
* Corresponding public key
* Corresponding account name

EOS and many other cryptosystems rely on ECDSA (Elliptic Curve Digital Signing Algorithm) techniques to secure transactions and prove ownership.  The specific elliptic curve used is called secp256k1. In this scheme, the private key is 256 bits (32 bytes), the public compressed-format key is 33 bytes (32 bytes plus 1-byte header), and the EOS account name is generally 12 characters.  The device's wallet then need only contain this information, which could be provisioned specifically for that device.

#### Transaction Signing Engine

As said above the EOS transactions are signed using ECDSA techniques and the secp256k1 curve.  Contiki does not have a ready-to-go ECC engine for this purpose so we have to improvise.  A few options we can look at are as follows:
* Hardware ECDSA (preferred)
* Software ECDSA with TinyDTLS
* Software ECDSA with a purpose built secp256k1 cryptolib like [this](https://github.com/bitcoin-core/secp256k1 ).

The hardware engine would be the preferred solution.  For Contiki, there is the possibility of using the newly supported TI second-generation IoT MCU, the cc13x2/cc26x2's ECC engine.  Specifically these devices contain something called the Large Number Engine that performs the ECC calculations much more efficiently than the MCU core, and can do it in parallel to boot.  It is, however, geared towards BLE 5 and TI-RTOS and supports only the NIST curves (e.g. secp256r1) out of the box.  To use this chip's hardware ECC engine to sign EOS transactions, we'd have to add the secp256k1 curve parameters into the driver, and adapt the TI-RTOS driven state machine into the Contiki framework.

TinyDTLS offer another approach.  TinyDTLS is already available for and works with Contiki-NG, and contains an ECDSA engine.  However, it too only supports the NIST curve secp256r1 (aka PRIME256).  Furthermore, the ECC engine appears to be optimized somewhat for this curve - and therefore some experimentation would be requried to find a way to adapt it to the secp256k1 curve needed for EOS transaction signing.


