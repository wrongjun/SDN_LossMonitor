"""Custom topology example
Two directly connected switches plus a host for each switch:
   host --- switch --- switch --- host
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

from mininet.node import RemoteController

# Traffic Control
from mininet.link import TCLink

REMOTE_CONTROLLER_IP = "127.0.0.1"

class MyTopo(Topo):
    def __init__(self):

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        leftHost = self.addHost('h1')
        rightHost = self.addHost('h2')
        leftSwitch = self.addSwitch('s1',protocols='OpenFlow13')
        rightSwitch = self.addSwitch('s2',protocols='OpenFlow13')
        ms = self.addSwitch('s3',protocols='OpenFlow13')
        #middleSwitch = self.addSwitch('s3',protocols='OpenFlow13')

        # Add links
        self.addLink(leftHost, leftSwitch,bw=100)
        # self.addLink(leftSwitch, rightSwitch,bw=100,loss=5)
        # self.addLink(leftSwitch, rightSwitch,bw=100,loss=5)
        self.addLink(leftSwitch, ms,bw=100,loss=5)
        self.addLink(ms, rightSwitch,bw=100)
        self.addLink(rightSwitch, rightHost,bw=100)
        #self.addLink(leftSwitch, middleSwitch,bw=100)
        #self.addLink(middleSwitch, rightSwitch,bw=100)


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    # simpleTest()
    # perfTest()
    topo = MyTopo()

    net = Mininet(topo=topo, link=TCLink,
                  controller=None,
                  autoStaticArp=True)
    net.addController("c0",
                      controller=RemoteController,
                      ip=REMOTE_CONTROLLER_IP,
                      port=6633)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    CLI(net)
    net.stop()



# sudo mn --custom topo.py --switch ovsk --controller remote