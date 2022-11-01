package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.lang.Runnable;
import java.lang.Thread;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * @author Aaron Gember-Jacobson
 * 
 * Edited : Harshita Singh
 */
public class Switch extends Device implements Runnable
{	


	//switch element class definition
	class SwitchElement{
		private long lastUpdate;
		private Iface outInterface; 


		public SwitchElement(long lastUpdate, Iface outInterface) {
			this.lastUpdate = lastUpdate;
			this.outInterface = outInterface;
		}
	
		public void setLastUpdate(long lastUpdate) {
			this.lastUpdate = lastUpdate;
		}
	
		public void setoutInterface(Iface outInterface) {
			this.outInterface = outInterface;
		}
	
		public long getLastUpdate() {
			return this.lastUpdate;
		}
	
		public Iface getoutInterface() {
			return this.outInterface;
		}
	}

	private ConcurrentHashMap<String, SwitchElement> switchMap; 
	private Thread t; 


	//monitoring the timeout for all elements, removing from table if timedout
	public void run(){
		try {

			while(true){
				if(switchMap!=null){
					for(Map.Entry<String, SwitchElement> entry : switchMap.entrySet()){
						long timeremaining = System.currentTimeMillis() - entry.getValue().getLastUpdate();
						if(timeremaining >= 15000L){
							switchMap.remove(entry.getKey());
							System.out.println("Entry Timeout - "+ entry.getValue());
						}


					}

				}
				Thread.sleep(200);
			}
			
		} catch (InterruptedException e) {
			e.printStackTrace(System.out);
			//TODO: handle exception
		}
	}

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		switchMap = new ConcurrentHashMap<String, SwitchElement>();
		t = new Thread(this);
		t.start();
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
		
		/********************************************************************/

		String sourceMAC = etherPacket.getSourceMAC().toString();
		String destinationMAC = etherPacket.getDestinationMAC().toString();
		SwitchElement entry = switchMap.get(destinationMAC);

		// No entry in the table for this destination --> broadcast to all interfaces 
		if(entry==null){

			System.out.println("Broadcasting to all interfaces...");
			for(Iface interf : interfaces.values()){
				if(!inIface.equals(interf)){
					sendPacket(etherPacket,interf);
				}
			}

		}

		//Entry found -> forward to correct interface
		else{
			System.out.println("Sending packet...");
			sendPacket(etherPacket,entry.getoutInterface());

		}

		//Check if switchmap contains information about the current source - if not - populate 

		if(switchMap.containsKey(sourceMAC)){
			System.out.println("Updating the forwarding table...");
			SwitchElement se  = switchMap.get(sourceMAC);
			se.setLastUpdate(System.currentTimeMillis());
			se.setoutInterface(inIface);
		}
		else{
			System.out.println("Adding entry to the forwarding table...");
			switchMap.put(sourceMAC, new SwitchElement(System.currentTimeMillis(), inIface));
		}

	}
}
