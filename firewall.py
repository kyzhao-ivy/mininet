from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str

log = core.getLogger()

class SimpleFirewall (object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

  def send_rule (self, src_ip, dst_ip, dl_type, nw_proto, action):
    msg = of.ofp_flow_mod()
    msg.match.dl_type = dl_type
    if src_ip:
      msg.match.nw_src = IPAddr(src_ip)
    if dst_ip:
      msg.match.nw_dst = IPAddr(dst_ip)
    if nw_proto:
      msg.match.nw_proto = nw_proto
    msg.actions.append(action)
    self.connection.send(msg)
    log.info(f"Adding flow for {src_ip} -> {dst_ip}, type {dl_type}, proto {nw_proto}, action {action}")

  def _handle_PacketIn (self, event):
    packet = event.parsed

    def drop ():
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out(data = event.ofp)
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        msg.actions = []
        event.connection.send(msg)
      log.info("Dropped packet from %s to %s", packet.src, packet.dst)

    if packet.type == packet.ARP_TYPE:
      log.info("Allowed ARP traffic from %s to %s", packet.src, packet.dst)
      return  # Allow all ARP traffic through
    elif packet.type == packet.IP_TYPE and packet.payload.protocol == packet.payload.ICMP_PROTOCOL:
      log.info("Allowed ICMP traffic from %s to %s", packet.src, packet.dst)
      return  # Allow all ICMP traffic through
    else:
      log.info("Packet from %s to %s not allowed by current rules, dropping.", packet.src, packet.dst)
      drop()  # Drop all other types of traffic

def launch ():
  def start_switch (event):
    log.info("Controlling %s", dpid_to_str(event.dpid))
    SimpleFirewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)

