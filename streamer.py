# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct

MAX_UDP_PAYLOAD = 1472
HEADER_FMT = "!HHH"          # msg_id, seq, total
HEADER_SIZE = struct.calcsize(HEADER_FMT)
MAX_DATA_SIZE = MAX_UDP_PAYLOAD - HEADER_SIZE

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

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        msg_id = self._next_msg_id & 0xFFFF
        self._next_msg_id = (self._next_msg_id + 1) & 0xFFFF

        total = (len(data_bytes) + MAX_DATA_SIZE - 1) // MAX_DATA_SIZE

        for seq in range(total):
            start = seq * MAX_DATA_SIZE
            chunk = data_bytes[start:start + MAX_DATA_SIZE]
            header = struct.pack(HEADER_FMT, msg_id, seq, total)
            self.socket.sendto(header + chunk, (self.dst_ip, self.dst_port))

    def recv(self) -> bytes:
        """Blocks until the next in-order message (by send-call) is ready."""
        # If we already have the next message fully assembled, return it immediately
        if self._expected_msg_id in self._complete:
            data = self._complete.pop(self._expected_msg_id)
            self._expected_msg_id = (self._expected_msg_id + 1) & 0xFFFF
            return data

        while True:
            packet, addr = self.socket.recvfrom()

            # Basic sanity: must at least contain header
            if len(packet) < HEADER_SIZE:
                continue

            msg_id, seq, total = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
            payload = packet[HEADER_SIZE:]

            # Create inflight entry if first time seeing this msg_id
            st = self._inflight.get(msg_id)
            if st is None:
                st = {"total": total, "chunks": {}}
                self._inflight[msg_id] = st
            else:
                # Sanity: ignore inconsistent 'total' for same msg_id
                if st["total"] != total:
                    continue

            if seq >= total:
                continue

            # Store chunk if new (ignore duplicates)
            st["chunks"].setdefault(seq, payload)

            # If this message is now complete, assemble and stash it
            if len(st["chunks"]) == st["total"]:
                assembled = b"".join(st["chunks"][i] for i in range(st["total"]))
                self._complete[msg_id] = assembled
                del self._inflight[msg_id]

                # If it’s the next expected message, return it now
                if msg_id == self._expected_msg_id:
                    data = self._complete.pop(self._expected_msg_id)
                    self._expected_msg_id = (self._expected_msg_id + 1) & 0xFFFF
                    return data

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # your code goes here, especially after you add ACKs and retransmissions.
        pass
