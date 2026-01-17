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

# Go-Back-N window size (max unacked DATA packets in flight)
WINDOW_SIZE = 100

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
        # msg_id -> {"total": int, "chunks": {seq: bytes}, "expected": int}
        # "expected" is the next in-order seq number we want (GBN-style).
        self._inflight_msg = {}
        self._complete_msg = {}   # msg_id -> bytes
        self._expected_msg_id = 0  # for recv() ordering of whole messages

        # FIN tracking
        self._fin_received = False  # True once we’ve seen a FIN from the peer

        # FIN ACK tracking
        self._fin_acks_received = False

        # Thread coordination
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._closed = False

        # Executor (listener + global sender loop)
        self._executor = ThreadPoolExecutor(max_workers=2)

        # --- Go-Back-N global state across ALL messages ---

        # (msg_id, seq) -> packet bytes for any unacked DATA packet
        self._outstanding = {}

        # Send order of packets (list of (msg_id, seq) in the order first sent)
        self._resend_queue = []

        # Per-message pending seqs: msg_id -> set of unacked seq indices
        self._pending_by_msg = {}

        # Explicit base tracking & timer restart on base advance
        # Current GBN base packet key (msg_id, seq), or None if none outstanding
        self._base_key = None
        # Time when the base last changed (used by retransmission timer)
        self._last_base_change_time = 0.0

        # Background threads
        self._listener_future = self._executor.submit(self._listener)
        self._sender_future = self._executor.submit(self._sender_loop)

    # ---------- Helper for base recomputation (GBN) ----------

    def _recompute_base_locked(self) -> None:
        """
        Recompute the GBN base (earliest unacked packet in send_order)
        and prune fully-ACKed prefixes from _resend_queue.

        Must be called WITH self._cv held.
        """
        # Drop any leading entries that are no longer outstanding.
        # This keeps _resend_queue roughly bounded by the current window size.
        while self._resend_queue and self._resend_queue[0] not in self._outstanding:
            self._resend_queue.pop(0)

        if self._resend_queue:
            new_base = self._resend_queue[0]
        else:
            new_base = None

        if new_base != self._base_key:
            self._base_key = new_base
            # Restart timer only when the base advances or becomes None
            self._last_base_change_time = time.time()

    # ---------- Listener Thread ----------

    def _listener(self) -> None:
        """Background thread: receive packets forever and assemble messages."""
        while True:
            # TODO: wrap your listening in a try/catch statement. Might cause exceptions
            packet, addr = self.socket.recvfrom()   # LossyUDP blocks but wakes every ~1s

            # LossyUDP returns b'' when stoprecv() was called
            if packet == b"":
                return

            if len(packet) < HEADER_SIZE + HASH_SIZE:
                # Corrupted packet, drop
                print("Corrupted packet, dropping")
                continue

            # Parse header
            try:
                flag, msg_id, seq, total = struct.unpack(
                    HEADER_FMT, packet[:HEADER_SIZE]
                )
            except struct.error:
                print("Error unpacking header")
                continue

            # Extract digest and payload
            digest = packet[HEADER_SIZE:HEADER_SIZE + HASH_SIZE]
            payload = packet[HEADER_SIZE + HASH_SIZE:]

            # Verify MD5(header + payload)
            header = packet[:HEADER_SIZE]
            expected_digest = hashlib.md5(header + payload).digest()
            if digest != expected_digest:
                # Corrupted packet, drop
                print("Corrupted packet, dropping")
                continue

            # Safety: ensure payload isn't larger than we expect
            if len(payload) > MAX_DATA_SIZE:
                # Misbehaving peer or corruption; drop
                print("Corrupted packet, dropping")
                continue

            # ---------- ACK packets ----------
            if flag == FLAG_ACK:
                with self._cv:
                    if self._closed:
                        return

                    # Track all ACKed (msg_id, seq) pairs (used for FIN)
                    if total == 0:  # FIN or FIN-ACK
                        self._fin_acks_received = True

                    # Only process DATA cumulative ACKs when total > 0 and seq in bounds
                    if total > 0 and 0 <= seq < total:
                        # pending may be None if all packets for this msg_id
                        # have already been ACKed and we deleted the entry,
                        # so late/duplicate ACKs are simply ignored.
                        pending = self._pending_by_msg.get(msg_id)
                        if pending is not None:
                            # Cumulative ACK: all 0..seq are considered received
                            to_remove = [s for s in pending if s <= seq]
                            for s in to_remove:
                                pending.remove(s)
                                key = (msg_id, s)
                                if key in self._outstanding:
                                    del self._outstanding[key]

                            if not pending:
                                del self._pending_by_msg[msg_id]

                            # Recompute base whenever outstanding changes
                            self._recompute_base_locked()

                    # Wake up sender loop / close() / send() if needed
                    self._cv.notify_all()

                continue

            # ---------- FIN packets ----------
            if flag == FLAG_FIN:
                with self._cv:
                    if self._closed:
                        return
                    # Mark that we have seen the peer's FIN
                    self._fin_received = True
                    self._cv.notify_all()

                # Always ACK a FIN (could be retransmitted)
                # Use seq=0, total=0 for FIN ACKs
                ack_packet = _build_packet(FLAG_ACK, msg_id, 0, 0, b"")
                self.socket.sendto(ack_packet, addr)
                continue

            # ---------- DATA packets (GBN-style receiver) ----------
            with self._cv:
                if self._closed:
                    return

                st = self._inflight_msg.get(msg_id)
                if st is None:
                    # First time we see this msg_id
                    st = {"total": total, "chunks": {}, "expected": 0}
                    self._inflight_msg[msg_id] = st
                else:
                    if st["total"] != total:
                        # Inconsistent header, drop
                        continue

                expected = st["expected"]

                # Decide whether to send an ACK and what seq to ACK
                send_ack = False
                ack_seq = None

                if seq == expected:
                    # In-order packet: accept and store
                    st["chunks"][seq] = payload
                    st["expected"] = expected + 1

                    # If we now have the full message, assemble and mark complete
                    if st["expected"] == st["total"]:
                        assembled = b"".join(
                            st["chunks"][i] for i in range(st["total"])
                        )
                        self._complete_msg[msg_id] = assembled
                        del self._inflight_msg[msg_id]
                        # Wake recv() in case it’s waiting
                        self._cv.notify_all()

                    # Highest in-order seq for this msg_id is now seq
                    send_ack = True
                    ack_seq = seq

                elif seq < expected:
                    # Duplicate packet: ignore payload, but ACK the last in-order seq
                    if expected > 0:
                        send_ack = True
                        ack_seq = expected - 1

                else:
                    # TODO: Out-of-order packets should be stored in a buffer and send ack later when the expected packet is received.
                    # Out-of-order (> expected): drop payload
                    # Only send ACK if we've at least received one in-order packet
                    if expected > 0:
                        send_ack = True
                        ack_seq = expected - 1

            # Send cumulative ACK for this msg_id outside the lock,
            # but only if we actually have a valid ACK to send.
            if send_ack:
                ack_packet = _build_packet(FLAG_ACK, msg_id, ack_seq, total, b"")
                self.socket.sendto(ack_packet, addr)

    # ---------- Sender / Retransmission Thread ----------

    def _sender_loop(self) -> None:
        """Global Go-Back-N retransmission loop across all messages."""
        while True:
            with self._cv:
                if self._closed:
                    return

                # Wait until we have at least one outstanding packet
                while not self._outstanding and not self._closed:
                    self._cv.wait()

                if self._closed:
                    return

                base_key = self._base_key
                base_time = self._last_base_change_time

            # Single timer for the current base
            time.sleep(ACK_TIMEOUT)

            with self._cv:
                if self._closed:
                    return

                # No outstanding means nothing to retransmit
                if not self._outstanding or self._base_key is None:
                    continue

                # If base changed (or base_time changed), the timer was restarted.
                if self._base_key != base_key or self._last_base_change_time != base_time:
                    continue

                # At this point:
                #  - base_key is still the same as when we started waiting
                #  - no new ACK has advanced the base
                #  => timeout for current base: Go-Back-N retransmission

                # By invariant, base is at index 0 of _resend_queue (if any).
                # Just retransmit from the front forward.
                for key in self._resend_queue:
                    if key in self._outstanding:
                        packet = self._outstanding[key]
                        self.socket.sendto(packet, (self.dst_ip, self.dst_port))
                # Timer will be restarted when/if base advances due to ACKs

    # ---------- Public API ----------

    def send(self, data_bytes: bytes) -> None:
        """Enqueue data for sending using global Go-Back-N (finite window).

        - Packets from all send() calls share a global send window.
        - At most WINDOW_SIZE unacked DATA packets can be in flight.
        - If the window is full, send() blocks until space is freed by ACKs.
        - Retransmission and timeout logic is handled by _sender_loop.
        """
        msg_id = self._next_msg_id & 0xFFFF
        self._next_msg_id = (self._next_msg_id + 1) & 0xFFFF

        total = (len(data_bytes) + MAX_DATA_SIZE - 1) // MAX_DATA_SIZE
        if total == 0:
            # Nothing to send
            return

        packets = []
        for seq in range(total):
            start = seq * MAX_DATA_SIZE
            chunk = data_bytes[start:start + MAX_DATA_SIZE]
            packet = _build_packet(FLAG_DATA, msg_id, seq, total, chunk)
            packets.append(packet)

        with self._cv:
            if self._closed:
                raise RuntimeError("Streamer is closed")

            # Initialize per-message pending seqs
            pending = set(range(total))
            self._pending_by_msg[msg_id] = pending

            # Add packets to global outstanding window and send them,
            # respecting WINDOW_SIZE
            for seq, packet in enumerate(packets):
                # If window is full, wait for ACKs to free space
                while len(self._outstanding) >= WINDOW_SIZE and not self._closed:
                    self._cv.wait()

                if self._closed:
                    raise RuntimeError("Streamer is closed")

                key = (msg_id, seq)
                if key not in self._outstanding:
                    self._resend_queue.append(key)
                self._outstanding[key] = packet
                self.socket.sendto(packet, (self.dst_ip, self.dst_port))

            # After adding new packets, recompute base and wake sender loop
            self._recompute_base_locked()
            self._cv.notify_all()

    def recv(self) -> bytes:
        with self._cv:
            while True:
                if self._closed:
                    raise RuntimeError("Streamer is closed")

                if self._expected_msg_id in self._complete_msg:
                    data = self._complete_msg.pop(self._expected_msg_id)
                    self._expected_msg_id = (self._expected_msg_id + 1) & 0xFFFF
                    return data

                self._cv.wait()

    def close(self) -> None:
        """Cleans up using a FIN/ACK-style teardown.

        Steps:
        1. Wait until all outstanding DATA packets are ACKed.
        2. Send a FIN packet.
        3. Wait for an ACK of the FIN (retransmit on timeout).
        4. Wait until a FIN packet has been received from the other side.
        5. Wait 2 seconds.
        6. Stop the listener/sender and return.
        """
        with self._cv:
            if self._closed:
                # Already closed; make close() idempotent
                return

            # Step 1: wait until all data packets are ACKed
            while (self._outstanding or self._pending_by_msg) and not self._closed:
                self._cv.wait(timeout=ACK_TIMEOUT)

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

                # FIN is considered ACKed when self._fin_acks_received is True
                if self._fin_acks_received:
                    break

                self._cv.wait(timeout=ACK_TIMEOUT)

                if self._fin_acks_received:
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

        # Wait for listener & sender loops to exit and clean up executor
        try:
            self._listener_future.result(timeout=2)
        except Exception:
            pass

        try:
            self._sender_future.result(timeout=2)
        except Exception:
            pass

        self._executor.shutdown(wait=True)
