#notes: http protocol? Is it always http? How do we figure out the others? ?

require 'packetfu'

#test null and xmas checks 
def test_null_xmas 
	#An Xmas packet (flags set accordingly)
	$tcp_pkt_xmas = PacketFu::TCPPacket.new
	$tcp_pkt_xmas.tcp_flags.urg=1
	$tcp_pkt_xmas.tcp_flags.psh=1
	$tcp_pkt_xmas.tcp_flags.fin=1
	$tcp_pkt_xmas.tcp_flags.ack=0
	$tcp_pkt_xmas.tcp_flags.syn=0
	$tcp_pkt_xmas.tcp_flags.rst=0

	$tcp_pkt_null = PacketFu::TCPPacket.new
	$tcp_pkt_null.tcp_flags.urg=0
	$tcp_pkt_null.tcp_flags.psh=0
	$tcp_pkt_null.tcp_flags.fin=0
	$tcp_pkt_null.tcp_flags.ack=0
	$tcp_pkt_null.tcp_flags.syn=0
	$tcp_pkt_null.tcp_flags.rst=0

	xmas_test = $tcp_pkt_xmas.tcp_flags.to_i
	null_test = $tcp_pkt_null.tcp_flags.to_i
	puts "The Xmas flags sum is #{xmas_test} and should be 41"
	puts "The null flags sum is #{null_test} and should be 0"

	if xmas_test == (URG + PSH + FIN) 	 				
		puts "Yes, test xmas scan has been caught" 
	end

	if null_test == 0	
		puts "Yes, test null scan has been caught" 
	end				
end




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

#totals for nmaps and shells
$s404s = 0
$nmaps = 0
$shells = 0

def web_log(_log)
	infile = File.open(_log, "r")
	while (word = infile.gets)
		if word =~ /4[0-9][0-9]/
			parse_line(word, "HTTP 4** Error found")	
			$s404s += 1
		end
		if word =~ /[n|N][m|M][a|A][p|P]/ 
			parse_line(word, "nmap found")
			$nmaps += 1
		end
		#used 3 in a row, not sure if that is too many or not enough
		if word =~ /\\x[0-9|a-f|A-F][0-9|a-f|A-F]([0-9|a-f|A-F])?(\\)?/
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

			flags_sum = -1
			flag_sum = pkt.tcp_flags.to_i

			#collect information 
			$src_ip = pkt.ip_src_readable
			$ip_protocol = pkt.ip_proto
			$payloadz = pkt.payload() 

			if flags_sum == (URG + PSH + FIN) 
				$incidence_number += 1			
				print_alert("Xmas attack", "TCP")
			elsif flags_sum == 0
				$incidence_number += 1
				print_alert("Null attack", "TCP")
			else 
				if pkt.tcp_dst == 80 
					ccard_check		
				end		
			end
		end

	end

end


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
		print_alert("Discoverty Credit Card", "TCP")
	elsif $payloadz =~ /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/
		$incidence_number += 1
		print_alert("Amex Credit Card", "TCP")
	elsif $payload =~ /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
		$incidence_number += 1
		print_alert("Master Credit Card", "TCP")	
	end
end

def main 

	#for testing null and xmas alarm technique
	#test_null_xmas

	if ARGV[0] == '-r'
		web_log(ARGV[1])	
	else
		live_stream
	end
	#puts "number 4** errors #{$s404s}"
	#puts "number of nmaps #{$nmaps}"
	#puts "number of shells #{$shells}"
end


main




