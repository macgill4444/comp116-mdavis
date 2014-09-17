require 'packetfu'

$incidence_number = 0
$ip_protocol = -1
$src_ip = -1
$payloadz = -1
 
packets = PacketFu::Capture.new(:start => true, :iface =>'eth0', :promisc => true, :filter => "tcp")


caught = false
while caught == false do 
	packets.stream.each do |p|
		pkt  = PacketFu::Packet.parse(p)
		#puts pkt.inspect()		
		
		flags_sum = 0
		pkt.tcp_flags.each do |f| 
			flags_sum += f
		end
		#collect information 
		$src_ip = pkt.ip_src_readable
		$ip_protocol = pkt.ip_proto
		$payloadz = pkt.payload() 
		puts "Source IP is  #{$src_ip}"
		puts "IP protocol is #{$ip_protocol}"
		puts "PAYLOAD IS         #{$payloadz}"	
		
			
		if flags_sum == 6
			puts "Xmas attack"
		elsif flags_sum == 0
			puts "Null alert"
			#print_alert("Null attack ")
		else 
			#puts "FLAGS SUM IS #{flags_sum}"
			puts "++++++++++++++++++++++++++++++++++++++++"
		end
	end

end

stream.show_live()

def print_alert(attack)
	puts "#{$incidence_number}. ALERT #{attack} is detected" 

end






