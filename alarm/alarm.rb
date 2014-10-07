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

$s404s = 0
$nmaps = 0
$shells = 0

def web_log(_log)
	infile = File.open(_log, "r")
	while (word = infile.gets)
		if word =~ /4[0-9][0-9]/
			parse_line(word, "HTTP 404 Error found")	
			$s404s += 1
		end
		if word =~ /[n|N][m|M][a|A][p|P]/ 
			parse_line(word, "nmap found")
			$nmaps += 1
		end
		if word =~ /x[0-9|a-f|A-F][0-9|a-f|A-F]{3,}/
		#if word =~ /(%21)?(%2F)?bin%2F?(sh)?(%2F)?(bash)?/
			$shells += 1
			parse_line(word, "Shellcode found")
		end	
		
	end
end

def parse_line(word, alert_ty)	
	$src_ip = word.scan(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/)
	$payloadz = word.scan(/".*\n/)
	$incidence_number += 1
	print_alert(alert_ty,"HTTP")
end


 
def live_stream
	packets = PacketFu::Capture.new(:start => true, :iface =>'en1', :promisc => true, :filter => "tcp")
		
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
def print_alert(attack, protoc)
	puts "\n"
	puts "#{$incidence_number}. ALERT #{attack} is detected from #{$src_ip} (#{protoc}) (#{$payloadz})!" 
	puts "\n"
	#clear vars
	$payloadz = ""
	$src_ip = -1
end

def ccard_check 
	if $payloadz =~ /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
		$incidence_number += 1
		print_alert("Discoverty Credit Card", "HTTP")
	elsif $payloadz =~ /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/
		$incidence_number += 1
		print_alert("Amex Credit Card", "HTTP")
	elsif $payload =~ /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
		$incidence_number += 1
		print_alert("Master Credit Card", "HTTP")	
	end
end

def main 
	if ARGV[0] == '-r'
		web_log(ARGV[1])	
	else
		live_stream
	end
	
	puts "404 errors #{$s404s}"
	puts "nmaps #{$nmaps}"
	puts "shells #{$shells}"
end

main


