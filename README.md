# Reliable Streaming Network Transport Simulator

This project implements a small, TCP-like **reliable streaming protocol** on top of UDP using a provided network simulator (`LossyUDP`). The goal is to understand how reliable transport works when the network can drop, reorder, or corrupt packets.

The main abstraction is the `Streamer` class, which behaves similarly to a very simplified TCP connection.

---

## What this project does

`Streamer` provides a **reliable byte stream** over an unreliable network:

- `send(bytes)` reliably sends data to the peer
- `recv()` returns the next complete message (in order)
- `close()` performs a graceful connection teardown

All reliability is implemented at the application level, on top of UDP.

---

## Core features

### 1. Chunking

Large messages are split into packets small enough to fit within the UDP payload limit. Each message is broken into fixed-size chunks and reassembled on the receiver side.

---

### 2. Packet format

Each packet contains:

- `flag` — DATA, ACK, or FIN
- `msg_id` — message identifier
- `seq` — sequence number within the message
- `total` — total number of packets in the message
- `md5(header + payload)` — corruption detection
- `payload`

---

### 3. Corruption detection

Packets include an MD5 hash of the header and payload. If a packet fails verification, it is dropped and later retransmitted by the sender.

---

### 4. Reordering tolerance

Packets may arrive out of order. The receiver buffers out-of-order packets and delivers data only when all earlier packets have arrived. ACKs are **cumulative** (Go-Back-N style).

---

### 5. Loss recovery (Go-Back-N)

The sender maintains a global window of outstanding packets, uses a single timeout based on the current “base” packet, and retransmits all unacknowledged packets on timeout. This allows multiple packets to be in flight at once.

---

### 6. Graceful connection teardown

`close()` performs a FIN/ACK-style shutdown similar to TCP:

1. Waits for all sent data to be acknowledged
2. Sends a FIN packet
3. Retransmits FIN if needed until ACKed
4. Waits for the peer’s FIN
5. Enters a short TIME-WAIT period
6. Shuts down cleanly

---

## Files

- **streamer.py**  
  The reliable transport protocol implementation.

- **lossy_socket.py**  
  Provided UDP simulator that can drop, delay, reorder, or corrupt packets.

- **test.py**  
  Simple test program that sends data between two endpoints.

---

## Running the test

Open **two terminals**.

### Terminal 1

```bash
python3 test.py 8000 8001 1
```

### Terminal 2

```bash
python3 test.py 8000 8001 2
```

The program sends sequences of numbers between the two processes and verifies correctness.

## Credits

The original project skeleton and assignment design were created by **[Steve Tarzia](https://stevetarzia.com)**.
This implementation builds on his provided framework and simulator.

## Summary

This project demonstrates how core transport-layer ideas (chunking, sequencing, acknowledgements, retransmissions, and connection teardown) can be built on top of an unreliable network. It is intentionally simpler than TCP, but captures the essential mechanics of reliable streaming communication.
