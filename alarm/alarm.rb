#notes: http protocol? Is it always http? How do we figure out the others? ?

require 'packetfu'

$incidence_number = 0
$ip_protocol = -1
$src_ip = -1
$payloadz = -1

URG = 32
ACK = 16
PSH = 8
RST = 4
SYN = 2
FIN = 1


def web_log(_log)
	infile = File.open(_log, "r")
	while (word = infile.gets)
		puts word
	end
end







 
def live_stream
	packets = PacketFu::Capture.new(:start => true, :iface =>'eth0', :promisc => true, :filter => "tcp")
		
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
					
			if flags_sum == (URG + PSH + SYN)
				$incidence_number += 1			
				print_alert("Xmas attack")
			elsif flags_sum == 0
				$incidence_number += 1
				print_alert("Null attack")
			else 
				if pkt.tcp_dst == 80 
					ccard_check		
				end		
			end
		end

	end

end

#NEED TO DEFINE PROTOCOL
def print_alert(attack)
	puts "\n"
	puts "#{$incidence_number}. ALERT #{attack} is detected from #{$src_ip} (HTTP) (#{$payloadz})!" 
	puts "\n"
end


def ccard_check 
	if /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match($payloadz)
		$incidence_number += 1
		print_alert("Discoverty Credit Card")
	elsif /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/.match($payloadz)
		$incidence_number += 1
		print_alert("Amex Credit Card")
	elsif /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/.match($payloadz)
		$incidence_number += 1
		print_alert("Master Credit Card")	
	end

	#clear payloadz
	$payloadz = "empty payload"
end

def main 
	if ARGV[0] == '-r'
		web_log(ARGV[1])	
	else
		live_stream
	end
end

main


