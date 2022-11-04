package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ARP;

import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

import java.util.Map;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.LinkedList;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 * @author KJ Choi 
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * 
	 Create a Queue for ARP 
	 */

	private Map<Integer, Queue> ipQueue = new HashMap<>();

	private Queue packetQ;

	
	/** RIP metrics for the router */
	private Map<Integer, RipTableEntry> ripTable;	

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

	class RipTableEntry
	{
		protected int ip, mask, nextHop, metric;
		protected long last_updated;
		
		public RipTableEntry(int ip, int mask, int metric, long last_updated)
		{
			this.ip = ip;
			this.mask = mask;
			this.nextHop = nextHop;
			this.metric = metric;
			this.last_updated = last_updated;
		}
	}

	/**
	 * Initialize RIP
	 * @author KJ Choi
	 */
	public void initRip()
	{
		this.ripTable = new ConcurrentHashMap<Integer, RipTableEntry>();

		for (Iface iface : this.interfaces.values())
		{
			int mask = iface.getSubnetMask();
			int ip = mask & iface.getIpAddress();
			routeTable.insert(ip, 0, mask, iface);
			ripTable.put(ip, new RipTableEntry(ip, mask, 0, -1));
			
			//send rip request
			sendRIP(0, null, iface);
		}
		
		Timer timer = new Timer(true);
		//unsolicited RIP response every 10 sec
		TimerTask unsolResponse = new TimerTask() 
		{
			public void run()
			{
				//System.out.println("Send unsolicited RIP response");
				for (Iface iface : interfaces.values())
				{ sendRIP(1, null, iface); }
			}
		};
		timer.schedule(unsolResponse, 0, 10000);

		//timeout
		TimerTask timeout = new TimerTask()
		{
			public void run()
			{
				for (RipTableEntry entry: ripTable.values())
				{
					//System.out.println(IPv4.fromIPv4Address(entry.ip) + "   :   metric:" +entry.metric+"   time:"+ entry.last_updated);
					if (entry.last_updated != -1 && System.currentTimeMillis() - entry.last_updated >= 30000)
					{
						//System.out.println("deleting "+IPv4.fromIPv4Address(entry.ip)+"   "+entry.mask);
						synchronized(ripTable)
						{ ripTable.remove(entry.ip); }
						routeTable.remove(entry.ip, entry.mask);
					}
				}
			}
		};
		timer.schedule(timeout, 0, 1000);
	}
	
	/**
	 * Send rip packet
	 * @param type 0: request, 1: response
	 * @param etherPacket received rip request
	 * @param iface out interface
	 */
	public void sendRIP(int type, Ethernet etherPacket, Iface outIface)
	{
                System.out.println("Generate RIP packet");

                //create new packet
                Ethernet ether = new Ethernet();
                IPv4 ip = new IPv4();
                UDP udp = new UDP();
                RIPv2 rip = new RIPv2();


                //Ether header
                ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());

                //IP header
                ip.setTtl((byte)64);
                ip.setProtocol(IPv4.PROTOCOL_UDP);

                //set src&dest ip
                ip.setSourceAddress(outIface.getIpAddress());

                if (etherPacket != null)
                { 
			IPv4 ipPacket = (IPv4)etherPacket.getPayload();
			ip.setDestinationAddress(ipPacket.getSourceAddress());

			ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		}

		else
		{ 
			ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9")); 
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
		}	

		//UDP header
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		
		//RIP
		if (type == 0)
		{ rip.setCommand(RIPv2.COMMAND_REQUEST); }
		else if (type == 1)
		{ rip.setCommand(RIPv2.COMMAND_RESPONSE); }
		else //invalid type
		{ return; }

		//rip entries
		List<RIPv2Entry> entries = new LinkedList<RIPv2Entry>();
		synchronized(this.ripTable) 
		{
			for(RipTableEntry ripEntry: this.ripTable.values())
			{
				//System.out.println("RIPTABLE: " + IPv4.fromIPv4Address(ripEntry.ip) + "  " + ripEntry.last_updated);
				RIPv2Entry entry = new RIPv2Entry(ripEntry.ip, ripEntry.mask, ripEntry.metric); 
				entries.add(entry);
			}

		}

                rip.setEntries(entries);
		udp.setPayload(rip);
                ip.setPayload(udp);
                ether.setPayload(ip);

                System.out.println("*** -> RIP packet: " +
                ether.toString().replace("\n", "\n\t"));

                this.sendPacket(ether, outIface);
        }

	public void handleRipPacket(Ethernet etherPacket, Iface inIface) 
	{
		System.out.println("Handle RIP packet");
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
                UDP udpPacket = (UDP)ipPacket.getPayload();

		RIPv2 rip = (RIPv2)udpPacket.getPayload();
		//handle request
		if (RIPv2.COMMAND_REQUEST == rip.getCommand())
		{
			System.out.println("Send RIP response");
			sendRIP(1, etherPacket, inIface);
			return;
		}

		//handle response
		System.out.println("Update RouteTable");

		List<RIPv2Entry> entries = rip.getEntries();

		for (RIPv2Entry entry : entries)
		{
			int mask = entry.getSubnetMask();
			int ip = mask & entry.getAddress();
			int nextHop = ipPacket.getSourceAddress();
			int metric = entry.getMetric();
			
			synchronized(this.ripTable)
			{
				if (this.ripTable.containsKey(ip))
				{	
					RipTableEntry localEntry = this.ripTable.get(ip);
					if (metric < localEntry.metric)
					{
						localEntry.last_updated = System.currentTimeMillis();
						localEntry.metric = metric+1;
						this.routeTable.update(ip, mask, nextHop, inIface);
					}

					if (metric >= 16)
					{
						RouteEntry routeEntry = this.routeTable.lookup(ip);
						if (routeEntry != null)
						{
							if (inIface.equals(routeEntry.getInterface()))
							{
								this.ripTable.remove(ip);
								this.routeTable.remove(ip, mask);
							}
						}
					}
				}
				else
				{
					if (metric < 16)
					{
						this.ripTable.put(ip, new RipTableEntry(ip, mask, metric+1, System.currentTimeMillis()));
						this.routeTable.insert(ip, nextHop, mask, inIface);
					}
				}
			}
		}
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

	private Ethernet generateARPPacket(byte[] destMAC, short opRequest, byte[] targethwAddr, byte[] targetprotocol,
			Iface inIface) {
		
		Ethernet ethernetHeader = new Ethernet();
        ethernetHeader.setEtherType(Ethernet.TYPE_ARP);
        ethernetHeader.setSourceMACAddress(inIface.getMacAddress().toBytes());
        ethernetHeader.setDestinationMACAddress(destMAC);
        // ARP header
        ARP arpHeader = new ARP();
        arpHeader.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arpHeader.setProtocolType(ARP.PROTO_TYPE_IP);
        arpHeader.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arpHeader.setProtocolAddressLength((byte) 4);
        arpHeader.setOpCode(opRequest);
        arpHeader.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
        arpHeader.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(inIface.getIpAddress()));
        arpHeader.setTargetHardwareAddress(targethwAddr);
        arpHeader.setTargetProtocolAddress(targetprotocol);
        // link
        ethernetHeader.setPayload(arpHeader);
        return ethernetHeader;
		
		
	}


	private void handleARPPacket(Ethernet etherPacket, Iface inIface){

		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
        { return; }
        System.out.println("Handling ARP packet");




		//Get Target protocol address 
		ARP arpPacket = (ARP)etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		int sourceIP = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();

		//Check for Request
		if(arpPacket.getOpCode() == ARP.OP_REQUEST){

			System.out.println("Received an ARP Request ");
			//confirm Target IP is req interface IP
			if(targetIp != inIface.getIpAddress()){
				return ;
			}


			//send reply for this request 

			Ethernet ethernetHeader = generateARPPacket(etherPacket.getSourceMACAddress(), ARP.OP_REPLY, arpPacket.getSenderHardwareAddress(), arpPacket.getSenderProtocolAddress(), inIface);
			 
            this.sendPacket(ethernetHeader, inIface);
            return;


		}
		else if(arpPacket.getOpCode()== ARP.OP_REPLY){

			//handle replies 

			System.out.println("Received an ARP Reply ");

			byte[] ip = arpPacket.getSenderProtocolAddress();
            byte[] mac = arpPacket.getSenderHardwareAddress();
            arpCache.insert(new MACAddress(mac), IPv4.toIPv4Address(ip));
            // send rest of the  packet with corresponding ip
            if (ipQueue.containsKey(IPv4.toIPv4Address(ip))) {
                Queue packetsQueue = ipQueue.get(IPv4.toIPv4Address(ip));
                while (!packetsQueue.isEmpty()) {
                    Ethernet packet = (Ethernet) packetsQueue.poll();
                    packet.setDestinationMACAddress(mac);
                    this.sendPacket(packet, inIface);

			 
		}
	}
}
	}

	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		
		//call handleRipPacket() if udp
		
		//ip destination 224.0.0.9
                if (IPv4.toIPv4Address("224.0.0.9") == ipPacket.getDestinationAddress())
                {
		       if (IPv4.PROTOCOL_UDP == ipPacket.getProtocol())
		       {
		       		UDP udpPacket = (UDP)ipPacket.getPayload();
                		//udp dest port 520
                		if (UDP.RIP_PORT == udpPacket.getDestinationPort())
                		{	
					this.handleRipPacket(etherPacket, inIface); 
					return ;
				}
		       }
		}

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

			/* System.out.println("Destination host unreachable");
                        this.generateIcmpPacket((byte)3, (byte)1, etherPacket);
                        return; */

			if(!ipQueue.containsKey(nextHop)){
				ipQueue.put(nextHop, new LinkedList<>());
				System.out.println("Wait for ARP reply for new ip" + IPv4.fromIPv4Address(nextHop));
			}

			generateARPRequest(etherPacket, nextHop, inIface, outIface);
			return;

	       	}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
		this.sendPacket(etherPacket, outIface);
	}

	private static final byte[] ZERO = {0, 0, 0, 0, 0, 0};
    private static final byte[] BROADCAST = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};

	/**
	 * @param etherPacket
	 * @param nextHop
	 * @param inIface
	 * @param outIface
	 */
	private void generateARPRequest(Ethernet etherPacket, final int nextHop, Iface inIface, final Iface outIface) {

		//Get details from the queue 

		Queue packetQ = ipQueue.get(nextHop);
		packetQ.add(etherPacket);


		//generate arp packet here 
		final Ethernet ether = generateARPPacket(BROADCAST, ARP.OP_REQUEST, ZERO, IPv4.toIPv4AddressBytes(nextHop), inIface);

		//Create atomically updatable elements 
		final AtomicReference<Ethernet> atomicEther = new AtomicReference<>(ether);
        final AtomicReference<Iface> atomicIface = new AtomicReference<>(outIface);
        // final AtomicReference<Ethernet> atomicOriginalPacket = new AtomicReference<>(etherPacket);
        final AtomicReference<Queue> atomicQueue = new AtomicReference<>(packetQ);


		Thread arpReplyWait = new Thread(new Runnable(){
			@Override
            public void run() {
                try {
                    int times = 3;
                    for (int i = 0; i < times; i++) {
                        System.out.println("----- Time " + i + atomicEther.get() + "-----");
                        sendPacket(atomicEther.get(), atomicIface.get());
                        Thread.sleep(1000);
                        if (arpCache.lookup(nextHop) != null) {
                            System.out.println("Have find the arp match in this turn !!");
                            return;
                        }
                    }
                    while (atomicQueue.get() != null && atomicQueue.get().peek() != null) {
                        atomicQueue.get().poll();
                    }
                    System.out.println("Destination host unreachable");
                    generateIcmpPacket((byte)3, (byte)1, etherPacket);
                        return;
                } catch (InterruptedException e) {
                    System.out.println(e);
                }
            }
        });

		arpReplyWait.start();
		return;

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
