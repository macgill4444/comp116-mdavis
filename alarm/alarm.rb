
require 'packetfu'

$incidence_number = 0
 
packets = PacketFu::Capture.new(:start => true, :iface =>'eth0', :promisc => true, :filter => "tcp")



stream.show_live()

caught = false
while caught == false do 
	packets.stream.each do |p|
		pkt  = PacketFu::Packet.parse(p)
		puts pkt.inspect()		
		puts "*********************************"
		flags_sum = 0
		pkt.tcp_flags.each do |f| 
			flags_sum += f
		end
		if flags_sum == 6
			$incidence_number++ 
			#print_alert("Xmas attack ")
		elsif flags_sum == 0
			$incidence_number++
			puts "Null alert"
			#print_alert("Null attack ")
		else 
			puts "FLAGS SUM IS #{flags_sum}"
			puts "++++++++++++++++++++++++++++++++++++++++"
		end
	end
	
	

end

def print_alert(attack)
	puts "#{$incidence_number}. ALERT #{attack} is detected" 

end






