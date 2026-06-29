# Distributed Messenger

A decentralized peer-to-peer messaging application written in Python.

## Overview

This project aims to create a messaging platform that minimizes reliance on centralized infrastructure by allowing devices to communicate directly with one another. The long-term vision is to provide private, secure communication while minimizing stored user data.

This project is currently in the early development stage, with the initial focus on building a reliable networking protocol before adding higher-level features.

## Goals

- Peer-to-peer communication
- No centralized messaging servers
- Automatic peer discovery
- End-to-end encrypted communication
- Minimal data retention
- Cross-platform compatibility
- Modular and extensible architecture

## Planned Architecture

```
Peer Node
│
├── Networking
├── Protocol
├── Peer Discovery
├── Encryption
└── Messaging
```

## Current Progress

- [x] Repository initialized
- [ ] Basic peer node
- [ ] Networking layer
- [ ] Message protocol
- [ ] Local peer discovery
- [ ] Distributed peer discovery
- [ ] Encryption
- [ ] Messaging interface

## Project Structure

```
distributed-messenger/
│
├── src/
│   ├── node.py
│   ├── networking.py
│   └── protocol.py
│
├── tests/
│
├── requirements.txt
└── README.md
```

## Technologies

- Python 3
- Python Standard Library (currently no external dependencies)

## Long-Term Vision

Create a decentralized messaging platform that gives users greater control over their communications and privacy while remaining easy to use.

This project is intended as both a learning experience in distributed systems and an exploration of decentralized communication technologies.
