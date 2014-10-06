require 'packetfu'

$incidence_number = 0
$ip_protocol = -1
$src_ip = -1
$payloadz = -1
 
def main
	packets = PacketFu::Capture.new(:start => true, :iface =>'eth0', :promisc => true)

	caught = false
	while caught == false do 
		packets.stream.each do |p|
			pkt  = PacketFu::Packet.parse(p)
			puts pkt.inspect()
			puts "*******************************************************"		
			puts pkt.proto
			puts "*******************************************************"		
			peek_pack = pkt.peek
			if peek_pack[0] == "T"
				puts "TRUE THIS IS A TCP"
			
				flags_sum = 0
				#collect information 
				#$src_ip = pkt.ip_src_readable
				#$ip_protocol = pkt.ip_proto
				#$payloadz = pkt.payload() 
				#puts "Source IP is  #{$src_ip}"
				#puts "IP protocol is #{$ip_protocol}"
				#puts "PAYLOAD IS         #{$payloadz}"	
			
				
				#if flag sum is 6, all flags on and xmas	
				if flags_sum == 6
					#puts "Xmas attack"
					#print_alert("Xmas attack ")				
				#if flag sum is 0 no flags on so null	
				elsif flags_sum == 0
					#puts "Null alert"
					#print_alert("Null attack ")
				else 
					#puts "FLAGS SUM IS #{flags_sum}"
					puts "++++++++++++++++++++++++++++++++++++++++"
				end
			end
		end

	end

end



def print_alert(attack)
	puts "#{$incidence_number}. ALERT #{attack} is detected" 
end

main




