# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import inet
from ryu.ofproto import ether

from ryu import utils
import binascii
from dnslib.dns import DNSRecord
import MySQLdb

#WEB_lacklist = ["www.taobao.com", "www.icbc.com.cn"]


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # add goto table 1 flow entry on table 0
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(table_id=1)]
        self.add_flow(datapath, 0, match, table_id=0, inst=inst)
        # install table-miss flow entry on table  1
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, table_id=1)
        # install udp_dst_port 50 flow entry on table 0 to match DNS request
        # packet.
        match = parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP, udp_dst=53)
        self.add_flow(datapath, 10, match, actions, table_id=0)

    def add_flow(self, datapath, priority, match, actions=[], table_id=0,
                 idle_timeout=0, hard_timeout=0, buffer_id=None, inst=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if not inst:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=table_id, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # judge "DNS packet"
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            if(pkt_ipv4.proto == inet.IPPROTO_UDP):
                pkt_udp = pkt.get_protocol(udp.udp)
                if 53 == pkt_udp.dst_port:
                    print " DNS request:dst_prot", pkt_udp.dst_port
                    self._badWeb_Potect(datapath, msg)
        else:
            self._forwarding(datapath, msg)

    # bad web  judge and protection
    def _badWeb_Potect(self, datapath, msg):
        print "in _badWeb_Potect"
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        hdata = utils.hex_array(msg.data)
        hdata = hdata.split(' ')
        hex_data = ''
        for hexdata in hdata:
            cc = hexdata.replace('0x', '')
            if len(cc) == 1:
                cc = '0%s' % cc
            hex_data = hex_data + cc
        # print "hex_data", hex_data
        # print 'pkt:', pkt

        hex_dnsdata = hex_data[84:]
        # print "dns hex data", hex_dnsdata
        dns_binary = binascii.unhexlify(hex_dnsdata)
        dns = DNSRecord.parse(dns_binary)
        # print 'dns:', dns
        dns
        web_name = dns.questions[0].get_qname().label
        web_name = ".".join(list(web_name))
        # print web_name

        try:
            conn = MySQLdb.connect(
                host='localhost', user='root', passwd='123456', db='web', port=3306)
            cur = conn.cursor()
            select = 'select * from WEB_lacklist where name="%s"' % web_name
            if(cur.execute(select)):
                print ' ilegal web  "%s", it`s dangerous! you  can`t to access it.' % web_name
                cur.close()
                conn.close()
                return
            else:
                print 'legal web "%s",you can access it.' % web_name
                cur.close()
                conn.close()
                self._forwarding(datapath, msg)
        except MySQLdb.Error, e:
            print "Mysql Error %d: %s" % (e.args[0], e.args[1])

        # for web in WEB_lacklist:
        #     if web_name == web:
        #         print "ilegal web, you  can`t to access."
        #         return
        # else:
        #     self._forwarding(datapath, msg)

    def _forwarding(self, datapath, msg):
        print "in _forwarding..."
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions,
                              idle_timeout=10, hard_timeout=10, table_id=1, buffer_id=msg.buffer_id)
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=10, table_id=1,
                              hard_timeout=10)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        if (out_port == ofproto.OFPP_FLOOD) or (msg.buffer_id == ofproto.OFP_NO_BUFFER):
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
