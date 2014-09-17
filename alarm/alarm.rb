#notes: can there be xmas and null with anything but a tcp? How do we do credit car example? Are we suppose to be able to parse through a file?

require 'packetfu'

$incidence_number = 0
$ip_protocol = -1
$src_ip = -1
$payloadz = -1

puts "working"
 
def live_stream
	packets = PacketFu::Capture.new(:start => true, :iface =>'eth0', :promisc => true, :filter => "tcp")
		
	puts "starting"
	tester
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
			puts pkt.tcp_dst
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



def print_alert(attack)
	puts "#{$incidence_number}. ALERT #{attack} is detected" 
end

def ccard_check
	#pl_ouput = Base64.encode64($payloadz)
	#puts pl_ouput
	if payloadz =~ "5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}"
		puts "Mastercard"
	end
	if $payloadz =~ "6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}"
		puts "Discovery"
	end
	if $payloadz =~ "3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}"
		puts "Amex"
	end
end

def ccard_check 
	#somethin = '6011asdfasdfasdfsdf6011-1234-1234-1234asdfasdfsdfasdfas'
	if /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match($payloadz)
		puts "Discovery card detected"
	elsif /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/.match($payloadz)
		puts "Amex detected"
	elsif /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match($payloadz)
		puts "Mastercard detected"
	else /"GET"/.match($payloadz)
		puts "WE GOTTA GET HERE WE GOT A GET!"
	end
end


live_stream




