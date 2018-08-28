#Metasploit
require 'msf/core'
class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	
	def initialize
		super(
			'Name'		=> 'Reset PJL passwords',
			'Version'	=> '$Revision: 1 $',
			'Description'	=> 'Module to change PJL passwords on printers',
			'Author'	=> 'BrianWGray',
			'License'	=> MSF_LICENSE
		)
		register_options(
			[
				Opt::RPORT(9100),
				OptString.new('OLDPASS', [true, 'Current PJL Password',"0"]),
				OptString.new('NEWPASS', [true, 'NEW PJL Password',"0"])			

			], self.class)
	end

	def run_host(ip)
		connect()
		
		pjlold = datastore['OLDPASS']
		pjlnew = datastore['NEWPASS']		

			#Build the PJL string buffer
			buf = "\e%-12345X@PJL JOB\r\n" +
			"@PJL JOB PASSWORD=#{pjlold}\r\n" +
			"@PJL DEFAULT PASSWORD=#{pjlnew}\r\n" +
			"@PJL INQUIRE PASSWORD\r\n" +
			"@PJL EOJ\r\n" +
			"\e%-12345X\r\n\x0d\x0a"

			sock.puts(buf)		
			data = sock.recv(1024)

		print_status("Received: #{data} from #{ip}")

		disconnect()
	end

end
