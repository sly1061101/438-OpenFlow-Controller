# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from copy import deepcopy
log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    self.ip_to_port = {'10.0.1.100':1,'10.0.2.100':2,'10.0.3.100':3}
    self.msg_queue = []
    self.routing_table = [['10.0.1.100/24','10.0.1.100','s1-eth1','10.0.1.1',1],['10.0.2.100/24', '10.0.2.100', 's1-eth2', '10.0.2.1', 2],['10.0.3.100/24', '10.0.3.100', 's1-eth3', '10.0.3.1', 3]]
    self.selfport_to_ip = {1:'10.0.1.1',2:'10.0.1.2',3:'10.0.1.3'}
    self.selfport_to_mac = {1:'04:ea:be:02:07:01',2:'04:ea:be:02:07:02',3:'04:ea:be:02:07:03'}
  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):

    """
    Implement switch-like behavior.
    """


    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # Learn the port for the source MAC
    self.mac_to_port[str(packet.src)] = packet_in.in_port # ... <add or update entry>
    if str(packet.dst) in self.mac_to_port.keys():
      self.resend_packet(packet_in,self.mac_to_port[str(packet.dst)])
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_src = packet.src
      msg.match.dl_dst = packet.dst
      msg.match.in_port = packet_in.in_port
      msg.idle_timeout = 60
      msg.hard_timeout = 120
      action = of.ofp_action_output(port = self.mac_to_port[str(packet.dst)])
      msg.actions.append(action)
      self.connection.send(msg)
    else:
      self.resend_packet(packet_in, of.OFPP_ALL)
    
    #if the port associated with the destination MAC of the packet is known:
      # Send packet out the associated port
      #self.resend_packet(packet_in, ...)

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      #log.debug("Installing flow...")
      # Maybe the log statement should have source/destination/port?

      #msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      #msg.match = of.ofp_match.from_packet(packet)
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      #< Add an output action, and send -- similar to resend_packet() >

    #else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      #self.resend_packet(packet_in, of.OFPP_ALL)
  def act_like_router(self, packet, packet_in):
    # packet.payload   # ip.v4 or arp strips ethernet header(frame header, MAC)
    # packet.payload.payload # ICMP or etc?
    # packet.payload.payload.payload # echo/unreach packet


    # if get ARP REQUEST packet
    if packet.type == ethernet.APR_TYPE :
      if (packet.payload.opcode == arp.REQUEST):
        tmpl1Eth = str(packet.src)
        packet.src = EthAddr(str(packet.dst))
        packet.dst = EthAddr(tmpl1Eth)

        tmpl2Eth = str(packet.payload.hwsrc)
        packet.payload.hwsrc = EthAddr("04:ea:be:02:07:01")
        packet.payload.hwdst = EthAddr(tmpl2Eth)

        tmpl2ip = str(packet.payload.protosrc)
        packet.payload.protosrc = IPAddr(str(packet.payload.protodst))
        packet.payload.protodst = IPAddr(tmpl2ip)
        packet.payload.opcode = arp.REPLY

        self.resend_packet(packet, packet_in.in_port)
        return

      if (packet.payload.opcode == arp.REPLY):
        self.mac_to_port[str(packet.payload.hwsrc)] = packet_in.in_port
        for i in range(len(self.msg_queue)):
          if msg_queue[i].payload.dstip  == packet.payload.protosrc :
            msg_queue[i].dst = packet.payload.hwsrc
            msg_queue[i].src = EthAddr(self.selfport_to_mac[packet_in.in_port])
            self.resend_packet(msg_queue[i],packet_in.in_port)
            del self.msg_queue[i]
            return

    if (packet.payload.type == ethernet.IP_TYPE):  # if it is IP packet
      # 1. if Ip is known 
      if packet.payload.hwdst in self.mac_to_port.keys():
        # then forward
        self.resend_packet(packet, self.mac_to_port[str(packet.payload.hwdst)])
      else:
        # deepcopy packet and put it in the queue?
        self.msg_queue.append(deepcopy(packet))
        # send ARP request
        # TODO:
        arp_request = arp()
        arp_request.hwsrc = EthAddr(self.selfport_to_mac[self.ip_to_port[packet.payload.dstip]])
        arp_request.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
        arp_request.opcode = arp.REQUEST
        arp_request.protosrc = IPAddr(self.selfport_to_ip[packet_in.in_port])
        arp_request.protodst = packet.payload.dstip
        ether = ethernet()
        ether.type = ethernet.ARP_REQUEST
        ether.dst = packet.src
        ether.src = EthAddr(self.selfport_to_mac[packet_in.in_port])
        ether.payload = arp_reply





  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    #self.act_like_switch(packet, packet_in)
    self.act_like_router(packet, packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)