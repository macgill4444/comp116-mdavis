require 'packetfu'

packets = PacketFu::Capture.new(:start => true, :iface =>'eth0', :promisc => true, :filter => "tcp and udp")

caught = false
while caught == false do 
	packets.stream.each do |p|
		pkt  = PacketFu::Packet.parse(p)
		puts pkt.inspect()		
		puts "*********************************"
		pkt.tcp_flags.each do |f| 
			puts f
		end
		puts "++++++++++++++++++++++++++++++++++++++++"
	end
	
	

end



stream.show_live()
