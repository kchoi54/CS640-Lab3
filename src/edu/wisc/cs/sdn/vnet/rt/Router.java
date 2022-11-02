package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;

		case Ethernet.TYPE_ARP:
			this.handleARPPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}

	private void handleARPPacket(Ethernet etherPacket, Iface inIface){
		
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		System.out.println("Handle IP packet");
		
		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
 		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }
        
		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		if (0 == ipPacket.getTtl())
		{
			System.out.println("Time exceeded");	
			this.generateIcmpPacket((byte)11, (byte)0, etherPacket); 
			return;
		}
        	
		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();
        
		// Check if packet is destined for one of router's interfaces
 		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{
				int prtcl = ipPacket.getProtocol();
				
				if(prtcl == IPv4.PROTOCOL_UDP || prtcl == IPv4.PROTOCOL_TCP)
				{
					System.out.println("Destination port unreachable");
			                this.generateIcmpPacket((byte)3, (byte)3, etherPacket);
					return;
				}

				if(prtcl == IPv4.PROTOCOL_ICMP)
				{
					ICMP icmp = (ICMP)ipPacket.getPayload();
					if(icmp.getIcmpType() == 8) 
					{
						System.out.println("Echo reply");
			                        this.generateIcmpPacket((byte)0, (byte)0, etherPacket);

					}
				}
				
				
				return; 
			}
		}
		
		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch)
		{
			System.out.println("Destination net unreachable");
                        this.generateIcmpPacket((byte)3, (byte)0, etherPacket);
			return; 
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface)
		{ return; }

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry)
		{
			System.out.println("Destination host unreachable");
                        this.generateIcmpPacket((byte)3, (byte)1, etherPacket);
                        return;

	       	}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
		this.sendPacket(etherPacket, outIface);
	}

	private void generateIcmpPacket(byte icmpType, byte icmpCode, Ethernet origEther)
	{
		System.out.println("Generate ICMP packet");
		
		//create new packet
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();


		//Ether header
		ether.setEtherType(Ethernet.TYPE_IPv4);

		//get ip packet of orig packet
		IPv4 origIp = (IPv4)origEther.getPayload();
		int srcAddr = origIp.getSourceAddress();

		//Find matching src route entry
		RouteEntry srcRouteEntry = this.routeTable.lookup(srcAddr);
		Iface outIface = srcRouteEntry.getInterface();

		//set src mac
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP source
                int nextHop = srcRouteEntry.getGatewayAddress();
                if (0 == nextHop)
                {nextHop = srcAddr; }

                //Set destination MAC address in Ethernet header
                ArpEntry arpEntry = this.arpCache.lookup(nextHop);
                if (null == arpEntry)
              	{ return; }

                ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		
		//IP header
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);

		//set src&dest ip
		if (icmpType != 0)
		{ ip.setSourceAddress(outIface.getIpAddress());} 
		
		else //echo reply
		{ ip.setSourceAddress(origIp.getDestinationAddress());}

		ip.setDestinationAddress(srcAddr);
		
		//ICMP header
		icmp.setIcmpType(icmpType);
		icmp.setIcmpCode(icmpCode);

		//Data
		if (icmpType != 0)
		{
			int origIpIhl = origIp.getHeaderLength() * 4;
			byte[] origIpSerial = origIp.serialize();

			byte[] payload = new byte[4+origIpIhl+8]; //padding(4) + ip header + payload(8)

			System.arraycopy(origIpSerial, 0, payload, 4, origIpIhl+8);
			data.setData(payload);
		}
		else //echo reply
		{ data = (Data)origIp.getPayload().getPayload(); }

		icmp.setPayload(data);
		ip.setPayload(icmp);
		ether.setPayload(ip);

		System.out.println("*** -> ICMP packet: " +
                ether.toString().replace("\n", "\n\t"));

		this.sendPacket(ether, outIface);
	}
}
