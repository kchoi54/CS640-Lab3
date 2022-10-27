package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import edu.wisc.cs.sdn.vnet.rt.ArpEntry;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import java.nio.ByteBuffer;

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
		/* @author KJ Choi                                                  */
		
		//check for IPv4
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) 
		{
			System.err.println("Packet type is not IPv4");
			return;
		}
		
		//verify checksum
		IPv4 header = (IPv4) etherPacket.getPayload();

		short chksm_received = header.getChecksum();
		header.resetChecksum();

		byte[] serialized = header.serialize();
		ByteBuffer bb = ByteBuffer.wrap(serialized, 10, 2);
		
		short chksm_calculated = bb.getShort();
		if (chksm_calculated != chksm_received) 
		{
			System.err.println("Checksum Error");
			return;
		}

		//decrement TTL
		byte ttl = (byte) (header.getTtl() - 1);
		if (ttl < 1)
		{
			System.err.println("TTL is zero");
			return;
		}
		header.setTtl(ttl);
		
		//recalculate checksum
		header.resetChecksum();
		serialized = header.serialize();
		header = (IPv4) header.deserialize(serialized, 0, serialized.length);
		etherPacket = (Ethernet) etherPacket.setPayload(header);


		//drop if packet is destined to one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (iface.getIpAddress() == header.getDestinationAddress())
			{
				return;
			}
		}

		//forward packet
		RouteEntry entry = this.routeTable.lookup(header.getDestinationAddress());
		if (entry == null)
		{
			System.err.println("Destination address not in the route table");
			return;
		}
		
		ArpEntry arp = this.arpCache.lookup(header.getDestinationAddress());
		if (arp == null)
		{
			System.err.println("Host not found");
			return;
		}

		byte[] destinationMacAddress = arp.getMac().toBytes();
		byte[] sourceMacAddress = entry.getInterface().getMacAddress().toBytes();
		
		if (destinationMacAddress == sourceMacAddress)
		{
			System.err.println("Cannot send packet back to the incoming interface");
			return;
		}
				
		etherPacket.setDestinationMACAddress(destinationMacAddress);
		etherPacket.setSourceMACAddress(sourceMacAddress);

		System.out.println("*** -> Sent packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		this.sendPacket(etherPacket, entry.getInterface());
			
		/********************************************************************/
	}
}
