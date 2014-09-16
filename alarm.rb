require 'packetfu'

packets = PacketFu::Capture.new(:start => true, :iface =>'eth0', :promisc => true)

caught = false
while caught == false do 
	packets.stream.each do |p|
		pkt  = PacketFu::Packet.parse(p)
		puts pkt
	end
end



stream.show_live()
