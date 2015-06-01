from mininet.topo import Topo
class MyTopo(Topo):
	def __init__(self):
	    Topo.__init__(self)
	    c=[]
	    a=[]
	    s=[]
	   
	    s.append(self.addSwitch('s1'))
	    s.append(self.addSwitch('s2'))
	    s.append(self.addSwitch('s3'))
	    
	    self.addLink(s[0],s[1],3,1)
	    self.addLink(s[1],s[2],3,1)
	    h1=self.addHost('h1',mac='00:00:00:00:00:01')
	    h2=self.addHost('h2',mac='00:00:00:00:00:02')
	    h3=self.addHost('h3',mac='00:00:00:00:00:03')
	    h4=self.addHost('h4',mac='00:00:00:00:00:04')
	    
            self.addLink(s[0],h1,1,1)
	    self.addLink(s[0],h2,2,1)
	    self.addLink(s[1],h3,2,1)
	    self.addLink(s[2],h4,2,1)
	    #self.addLink(e[1],h3)
topos={'mytopo':(lambda:MyTopo())}

# mn --mac --custom /home/hl/text/topo3.py --topo mytopo --switch ovsk,protocols=OpenFlow13 --controller remote -x
