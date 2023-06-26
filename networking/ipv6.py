import struct


class IPv6:
    def __init__(self, raw_data):
        version_traffic_flow, payload_length, next_header, hop_limit, src, target = struct.unpack('!IHBB16s16s', raw_data[:40])
        self.version = (version_traffic_flow >> 28) & 0x0F
        self.traffic_class = (version_traffic_flow >> 20) & 0xFF
        self.flow_label = version_traffic_flow & 0xFFFFF
        self.payload_length = payload_length
        self.next_header = next_header
        self.hop_limit = hop_limit
        self.src = self.ipv6(src)
        self.target = self.ipv6(target)
        self.data = raw_data[40:]

    def ipv6(self, addr):
        # Retorna o endereço IPv6 formatado corretamente
        return ':'.join('{:02x}{:02x}'.format(a, b) for a, b in zip(addr[:8], addr[8:]))
