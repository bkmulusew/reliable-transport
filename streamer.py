# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import hashlib

FLAG_DATA = 0
FLAG_ACK = 1
FLAG_FIN = 2

MAX_UDP_PAYLOAD = 1472

# Header: flag, msg_id, seq, total
HEADER_FMT = "!BHHH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# MD5 hash size in bytes
HASH_SIZE = 16

# Maximum data per packet so that header + hash + payload <= MAX_UDP_PAYLOAD
MAX_DATA_SIZE = MAX_UDP_PAYLOAD - HEADER_SIZE - HASH_SIZE

ACK_TIMEOUT = 0.25  # seconds

def _build_packet(flag: int, msg_id: int, seq: int, total: int, payload: bytes) -> bytes:
    """
    Build a packet:
    [HEADER (flag,msg_id,seq,total)] [MD5(header+payload)] [payload]
    Ensures the final packet size does not exceed MAX_UDP_PAYLOAD.
    """
    header = struct.pack(HEADER_FMT, flag, msg_id, seq, total)
    digest = hashlib.md5(header + payload).digest()  # 16 bytes
    packet = header + digest + payload

    if len(packet) > MAX_UDP_PAYLOAD:
        raise ValueError("Packet larger than MAX_UDP_PAYLOAD")

    return packet

class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self._next_msg_id = 0  # increments per send()

        # Receiver state
        self._expected_msg_id = 0
        self._inflight = {}   # msg_id -> {"total": int, "chunks": {seq: bytes}}
        self._complete = {}   # msg_id -> bytes

        # ACK tracking: set of (msg_id, seq) tuples that have been ACKed
        self._acked_packets = set()

        # FIN tracking
        self._fin_received = False  # True once we’ve seen a FIN from the peer

        # Thread coordination
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._closed = False

        # IMPORTANT: keep executor as an attribute (don’t let it get GC’d)
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._listener_future = self._executor.submit(self._listener)

    def _listener(self) -> None:
        """Background thread: receive packets forever and assemble messages."""
        while True:
            packet, addr = self.socket.recvfrom()   # LossyUDP blocks but wakes every ~1s

            # LossyUDP returns b'' when stoprecv() was called
            if packet == b"":
                return

            if len(packet) < HEADER_SIZE + HASH_SIZE:
                continue

            # Parse header
            try:
                flag, msg_id, seq, total = struct.unpack(
                    HEADER_FMT, packet[:HEADER_SIZE]
                )
            except struct.error:
                continue

            # Extract digest and payload
            digest = packet[HEADER_SIZE:HEADER_SIZE + HASH_SIZE]
            payload = packet[HEADER_SIZE + HASH_SIZE:]

            # Verify MD5(header + payload)
            header = packet[:HEADER_SIZE]
            expected_digest = hashlib.md5(header + payload).digest()
            if digest != expected_digest:
                # Corrupted packet, drop
                continue

            # Safety: ensure payload isn't larger than we expect
            if len(payload) > MAX_DATA_SIZE:
                # Misbehaving peer or corruption; drop
                continue

            # Handle ACKs (for DATA and FIN packets)
            if flag == FLAG_ACK:
                with self._cv:
                    if self._closed:
                        return
                    # Record that this (msg_id, seq) was ACKed
                    self._acked_packets.add((msg_id, seq))
                    self._cv.notify_all()
                continue

            # Handle FIN packets
            if flag == FLAG_FIN:
                with self._cv:
                    if self._closed:
                        return
                    # Mark that we have seen the peer's FIN
                    self._fin_received = True
                    self._cv.notify_all()

                # Always ACK a FIN (could be retransmitted)
                # Use seq=0 for FIN ACKs
                ack_packet = _build_packet(FLAG_ACK, msg_id, 0, 0, b"")
                self.socket.sendto(ack_packet, addr)
                continue

            # Otherwise, it’s a DATA packet
            with self._cv:
                if self._closed:
                    return

                st = self._inflight.get(msg_id)
                if st is None:
                    st = {"total": total, "chunks": {}}
                    self._inflight[msg_id] = st
                else:
                    if st["total"] != total:
                        # Inconsistent header, drop
                        continue

                if seq >= total:
                    # Invalid seq index
                    continue

                # Store chunk if new
                if seq not in st["chunks"]:
                    st["chunks"][seq] = payload

                # If we now have a full message, assemble and mark complete
                if len(st["chunks"]) == st["total"]:
                    assembled = b"".join(st["chunks"][i] for i in range(st["total"]))
                    self._complete[msg_id] = assembled
                    del self._inflight[msg_id]

                    # Wake recv() in case it’s waiting for this (or future) msg
                    self._cv.notify_all()

            # Send ACK for this specific (msg_id, seq) outside the lock.
            ack_packet = _build_packet(FLAG_ACK, msg_id, seq, total, b"")
            self.socket.sendto(ack_packet, addr)

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        msg_id = self._next_msg_id & 0xFFFF
        self._next_msg_id = (self._next_msg_id + 1) & 0xFFFF

        total = (len(data_bytes) + MAX_DATA_SIZE - 1) // MAX_DATA_SIZE
        if total == 0:
            # Nothing to send
            return

        # Build all packets so we can retransmit them on timeout
        packets = []
        for seq in range(total):
            start = seq * MAX_DATA_SIZE
            chunk = data_bytes[start:start + MAX_DATA_SIZE]

            # Build packet with MD5 checksum and size safety
            packet = _build_packet(FLAG_DATA, msg_id, seq, total, chunk)
            packets.append(packet)
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))

        pending_seqs = set(range(total))

        # Retransmit only packets whose (msg_id, seq) haven't been ACKed
        while pending_seqs:
            with self._cv:
                if self._closed:
                    raise RuntimeError("Streamer is closed")

                # Remove any sequences that have been ACKed
                newly_acked = {
                    seq for seq in pending_seqs
                    if (msg_id, seq) in self._acked_packets
                }
                for seq in newly_acked:
                    pending_seqs.remove(seq)
                    self._acked_packets.remove((msg_id, seq))

                if not pending_seqs:
                    # All packets for this message were ACKed
                    return

                # Wait up to ACK_TIMEOUT for more ACKs
                self._cv.wait(timeout=ACK_TIMEOUT)

                if self._closed:
                    raise RuntimeError("Streamer is closed")

                # Loop; on timeout we fall through and retransmit remaining

            # Timeout or spurious wakeup: retransmit only unacked packets
            for seq in pending_seqs:
                self.socket.sendto(packets[seq], (self.dst_ip, self.dst_port))

    def recv(self) -> bytes:
        with self._cv:
            while True:
                if self._closed:
                    raise RuntimeError("Streamer is closed")

                if self._expected_msg_id in self._complete:
                    data = self._complete.pop(self._expected_msg_id)
                    self._expected_msg_id = (self._expected_msg_id + 1) & 0xFFFF
                    return data

                self._cv.wait()

    def close(self) -> None:
        """Cleans up using a FIN/ACK-style teardown.

        Steps:
        1. (Stop-and-wait send() already ensures last data was ACKed.)
        2. Send a FIN packet.
        3. Wait for an ACK of the FIN (retransmit on timeout).
        4. Wait until a FIN packet has been received from the other side.
        5. Wait 2 seconds.
        6. Stop the listener and return.
        """
        with self._cv:
            if self._closed:
                # Already closed; make close() idempotent
                return

        # Allocate a msg_id for the FIN
        fin_msg_id = self._next_msg_id & 0xFFFF
        self._next_msg_id = (self._next_msg_id + 1) & 0xFFFF

        fin_packet = _build_packet(FLAG_FIN, fin_msg_id, 0, 0, b"")

        # Step 2 & 3: send FIN and wait for ACK with retransmission
        while True:
            # Send FIN
            self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))

            with self._cv:
                if self._closed:
                    break

                # FIN is considered ACKed when (fin_msg_id, 0) is ACKed
                if (fin_msg_id, 0) in self._acked_packets:
                    self._acked_packets.remove((fin_msg_id, 0))
                    break

                self._cv.wait(timeout=ACK_TIMEOUT)

                if (fin_msg_id, 0) in self._acked_packets:
                    self._acked_packets.remove((fin_msg_id, 0))
                    break

                if self._closed:
                    break
                # Otherwise, timeout: loop to retransmit FIN

        # Step 4: wait until we have received the peer’s FIN
        with self._cv:
            while not self._fin_received and not self._closed:
                self._cv.wait(timeout=ACK_TIMEOUT)

        # Step 5: wait two seconds (like TCP TIME-WAIT)
        time.sleep(2.0)

        # Step 6: stop listener and mark closed
        self.socket.stoprecv()

        with self._cv:
            self._closed = True
            self._cv.notify_all()

        # Wait for listener to exit and clean up executor
        try:
            self._listener_future.result(timeout=2)
        except Exception:
            pass

        self._executor.shutdown(wait=True)
