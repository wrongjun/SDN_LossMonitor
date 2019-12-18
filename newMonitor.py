# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.topology import event
# Below is the library used for topo discovery
from ryu.topology.api import get_switch, get_link

import copy

class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.topo_raw_switches = []
        self.topo_raw_links = []
        self.monitor_thread = hub.spawn(self._monitor)
        self.link =[]
        self.maximumBandwidth ={}
        # Measure the number of package being transfer in each port of each switch
        self.totalOutPackage ={}
        self.avaliablePort={}
        self.specialPort={}

        #measure of success transmitted package and bytes
        self.tx_msg ={}
        #data for last check
        self.preData = {}
        self.newData ={}
        self.resData={}
        
    def set_path(self,datapath,incoming,outgoing):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=incoming)
        actions = [parser.OFPActionOutput(outgoing)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, priority=0, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
    def switch_features_handler(self , ev):
        print("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.id == 1 :
            print('set path for s1')
            #self.set_path(datapath,1,ofproto.OFPP_CONTROLLER)
            self.set_path(datapath,1,2)
            self.set_path(datapath,2,1)


        if datapath.id == 2:
            print('set path for s2')
            self.set_path(datapath,1,2)
            self.set_path(datapath,2,1)
            #self.set_path(datapath,2,ofproto.OFPP_CONTROLLER)
            # self.group_mod01(datapath,2,1,3,50,50)
            # actions = [parser.OFPActionSetField(ip_dscp = 1),
            # parser.OFPActionGroup(group_id = 1)]
            # priority = 100
            # match = parser.OFPMatch(in_port= 2)
            # self.add_flow(datapath, priority , match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.transferData =""

            print('-----------link topology--------------')
            self.links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no,'dst_port':link.dst.port_no}) for link in self.topo_raw_links]
            print(self.links)
            #print(self.totalOutPackage)
            print('----------------topology end---------------')
            
            for dp in self.datapaths.values():
                self._request_stats(dp)

            try:

                print('from             port     to               port     send_pks send_bytes tx_pks tx_bytes loss_pks loss_bytes')
                for x in self.links:
                    switch_id = x[0]
                    port = x[2]['port']
                    send_pk=self.totalOutPackage[switch_id][port]['packet_count']
                    send_by=self.totalOutPackage[switch_id][port]['tmp_byte_count']
                    tx_pk =self.tx_msg[switch_id][port]['tx_packets']
                    tx_by = self.tx_msg[switch_id][port]['tx_bytes']

                    tmp_D = [send_pk,send_by,tx_pk,tx_by]
                    self.newData[switch_id][port]=tmp_D
                    tmp_pre = self.preData[switch_id][port]

                    tmp_res = [0,0,0,0]
                    for z in range(0,4):
                        tmp_res[z] = tmp_D[z] - tmp_pre[z]
                    #print(self.resData)
                    loss_pk = (tmp_res[0] - tmp_res[2])/tmp_res[0] *100
                    loss_by = (tmp_res[1] - tmp_res[3])/tmp_res[3] *100
                    if ((tmp_res[0])<100):
                        loss_pk = 0.0000001
                        loss_by = 0.0000001
                    if (1 / loss_pk < 0):
                        loss_pk = 0.0000001
                        loss_by = 0.0000001
                    
                    self.logger.info('%016x %8x %016x %8x %8d %8d %8d %8d %2f %2f',
                    switch_id,port,x[1],x[2]['dst_port'],
                    tmp_res[0],tmp_res[1],tmp_res[2],tmp_res[3],loss_pk,loss_by)

                    self.preData[switch_id][port] = tmp_D

                # self.preData[switch_id][port] = self.newData[switch_id][port]

                # self.logger.info('%016x %8x %016x %8x %8d %8d %8d %8d %2f %2f',
                # switch_id,port,x[1],x[2]['dst_port'],
                # send_pk,send_by,tx_pk,tx_by,loss_pk,loss_by)
            except:
                print('error')

            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPPortDescStatsRequest(datapath, 0,)
        datapath.send_msg(req)

        req = parser.OFPFlowStatsRequest(datapath, 0,
                                            ofproto.OFPTT_ALL,
                                            ofproto.OFPP_ANY, ofproto.OFPG_ANY)

        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        
        tmp={}
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            tmp[stat.port_no]={'tx_packets':stat.rx_packets,'tx_bytes':stat.rx_bytes}
        self.tx_msg[ev.msg.datapath.id] = tmp

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        ports = []
        tmp={}
        #preset new data prevData resData
        for p in ev.msg.body:
            tmp[p.port_no] = p.curr_speed
            if(p.curr_speed>0):
                ports.append(p.port_no)
        self.maximumBandwidth[ev.msg.datapath.id] = tmp
        self.avaliablePort[ev.msg.datapath.id]=ports
        #print(self.avaliablePort)
        #print(self.maximumBandwidth)


    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        # The Function get_switch(self, None) outputs the list of switches.
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))
        """
        Now you have saved the links and switches of the topo. So you could do all sort of stuf with them. 
        """
        tmp_p={}
        tmp_y ={}
        tmp_id =0
        for p in ev.switch.ports:
            tmp_id = p.dpid
            tmp_p[p.port_no] =[0,0,0,0]
            tmp_y[p.port_no] =[0,0,0,0]
        self.newData[tmp_id] = tmp_p
        self.preData[tmp_id] = tmp_y
        # self.logger.info(self.newData)
        # self.logger.info(self.preData)

        #req = parser.OFPFlowStatsRequest(datapath)
        #datapath.send_msg(req)


        print(" \t" + "Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t" + str(s))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        tmp = {} 
       
        for i in self.avaliablePort[ev.msg.datapath.id]:
            tmp_packet_count = 0
            tmp_byte_count = 0
            for stat in ev.msg.body:
                # print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.')
                #flows.append('packet_count=%d byte_count=%d '
                #            'instructions=%s' %
                #            (stat.packet_count, stat.byte_count,stat.instructions))
                # print('---------------')
                # print('port='+ str(i))
                # print('--------------------')
                # print('result:')
                # print(str(stat.instructions[0]).find('port='+ str(i)))
                # print('-----------------')
                #4294967293 is the going to all port
                if ((str(stat.instructions[0]).find('port='+ str(i))!=-1) | (str(stat.instructions[0]).find('port='+ str(4294967293))!=-1)):
                    tmp_packet_count += stat.packet_count
                    tmp_byte_count += stat.byte_count
                # print('<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
            tmp[i]={'packet_count':tmp_packet_count,'tmp_byte_count':tmp_byte_count}
        self.totalOutPackage[ev.msg.datapath.id]=tmp
        #self.logger.info('FlowStats: %s', flows)

    """
    This event is fired when a switch leaves the topo. i.e. fails.
    """

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")