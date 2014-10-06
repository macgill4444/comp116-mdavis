#notes: can there be xmas and null with anything but a tcp? How do we do credit car example? Are we suppose to be able to parse through a file?

require 'packetfu'

$incidence_number = 0
$ip_protocol = -1
$src_ip = -1
$payloadz = -1

 
def live_stream
	packets = PacketFu::Capture.new(:start => true, :iface =>'eth0', :promisc => true, :filter => "tcp")
		
	puts "starting"
	
	caught = false
	while caught == false do 
		packets.stream.each do |p|
			pkt = PacketFu::Packet.parse(p)
			#puts pkt.proto
			#puts pkt.inspect()		
			
			flags_sum = 0
			pkt.tcp_flags.each do |f| 
				flags_sum += f
			end
			#collect information 
			$src_ip = pkt.ip_src_readable
			$ip_protocol = pkt.ip_proto
			$payloadz = pkt.payload() 
			#puts "Source IP is  #{$src_ip}"
			#puts "IP protocol is #{$ip_protocol}"
			#puts "PAYLOAD IS         #{$payloadz}"	
					
			#destinatino port for TCP, 80 is http
			#puts pkt.tcp_dst
			#puts "Destinatino port is above me..."
				
			#if flag sum is 6, all flags on and xmas	
			if flags_sum == 6
				print_alert("Xmas attack")
				$incidence_number += 1			
			#if flag sum is 0 no flags on so null	
			elsif flags_sum == 0
				$incidence_number += 1
				print_alert("Null attack ")
			else 
				if pkt.tcp_dst == 80 
					#puts "is a http req"
					ccard_check		
				end		
			end
		end

	end

end

#{incident_number}. ALERT: #{attack} is detected from #{source IP address} (#{protocol}) (#{payload})!


def print_alert(attack)
	puts "#{$incidence_number}. ALERT #{attack} is detected from #{$src_ip} (#{$ip_protocol}) (#{$payloadz}" 
end




def ccard_check 
	if /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match($payloadz)
		$incidence_number += 1
		print_alert("Discoverty Credit Card")
	elsif /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/.match($payloadz)
		$incidence_number += 1
		puts "Amex detected"
	elsif /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match($payloadz)
		$incidence_number += 1
		puts "Mastercard detected"
	end
	#clear payloadz
	$payloadz = "empty payload"
end


live_stream




