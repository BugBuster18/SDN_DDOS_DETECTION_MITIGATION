from mininet.topo import Topo
from mininet.net import Mininet
# from mininet.node import CPULimitedHost
from mininet.link import TCLink
# from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController
# from time import sleep

import sys
import os

class MyTopo( Topo ):

    def build( self, bw=None, cpu=1.0/20 ):
        # Optional link capacity (Mbit/s). None keeps the original unlimited TCLink behaviour.
        lk = {"bw": bw} if bw else {}
        hk = {"cpu": cpu} if cpu else {}

        s1 = self.addSwitch( 's1', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h1 = self.addHost( 'h1', **hk, mac="00:00:00:00:00:01", ip="10.0.0.1/24" )
        h2 = self.addHost( 'h2', **hk, mac="00:00:00:00:00:02", ip="10.0.0.2/24" )
        h3 = self.addHost( 'h3', **hk, mac="00:00:00:00:00:03", ip="10.0.0.3/24" )    

        s2 = self.addSwitch( 's2', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h4 = self.addHost( 'h4', **hk, mac="00:00:00:00:00:04", ip="10.0.0.4/24" )
        h5 = self.addHost( 'h5', **hk, mac="00:00:00:00:00:05", ip="10.0.0.5/24" )
        h6 = self.addHost( 'h6', **hk, mac="00:00:00:00:00:06", ip="10.0.0.6/24" )

        s3 = self.addSwitch( 's3', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h7 = self.addHost( 'h7', **hk, mac="00:00:00:00:00:07", ip="10.0.0.7/24" )
        h8 = self.addHost( 'h8', **hk, mac="00:00:00:00:00:08", ip="10.0.0.8/24" )
        h9 = self.addHost( 'h9', **hk, mac="00:00:00:00:00:09", ip="10.0.0.9/24" )

        s4 = self.addSwitch( 's4', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h10 = self.addHost( 'h10', **hk, mac="00:00:00:00:00:10", ip="10.0.0.10/24" )
        h11 = self.addHost( 'h11', **hk, mac="00:00:00:00:00:11", ip="10.0.0.11/24" )
        h12 = self.addHost( 'h12', **hk, mac="00:00:00:00:00:12", ip="10.0.0.12/24" )

        s5 = self.addSwitch( 's5', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h13 = self.addHost( 'h13', **hk, mac="00:00:00:00:00:13", ip="10.0.0.13/24" )
        h14 = self.addHost( 'h14', **hk, mac="00:00:00:00:00:14", ip="10.0.0.14/24" )
        h15 = self.addHost( 'h15', **hk, mac="00:00:00:00:00:15", ip="10.0.0.15/24" )

        s6 = self.addSwitch( 's6', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h16 = self.addHost( 'h16', **hk, mac="00:00:00:00:00:16", ip="10.0.0.16/24" )
        h17 = self.addHost( 'h17', **hk, mac="00:00:00:00:00:17", ip="10.0.0.17/24" )
        h18 = self.addHost( 'h18', **hk, mac="00:00:00:00:00:18", ip="10.0.0.18/24" )

        # Add links

        self.addLink( h1, s1, **lk )
        self.addLink( h2, s1, **lk )
        self.addLink( h3, s1, **lk )

        self.addLink( h4, s2, **lk )
        self.addLink( h5, s2, **lk )
        self.addLink( h6, s2, **lk )

        self.addLink( h7, s3, **lk )
        self.addLink( h8, s3, **lk )
        self.addLink( h9, s3, **lk )

        self.addLink( h10, s4, **lk )
        self.addLink( h11, s4, **lk )
        self.addLink( h12, s4, **lk )

        self.addLink( h13, s5, **lk )
        self.addLink( h14, s5, **lk )
        self.addLink( h15, s5, **lk )

        self.addLink( h16, s6, **lk )
        self.addLink( h17, s6, **lk )
        self.addLink( h18, s6, **lk )

        self.addLink( s1, s2, **lk )
        self.addLink( s2, s3, **lk )
        self.addLink( s3, s4, **lk )
        self.addLink( s4, s5, **lk )
        self.addLink( s5, s6, **lk )

def startNetwork():

    topo = MyTopo()
    ctrl_ip = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('CONTROLLER_IP', '127.0.0.1')
    c0 = RemoteController('c0', ip=ctrl_ip, port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    startNetwork()
