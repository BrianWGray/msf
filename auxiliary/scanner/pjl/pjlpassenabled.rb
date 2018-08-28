#Metasploit
require 'msf/core'
class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'		=> 'PJL password scanner',
			'Version'	=> '$Revision: 1 $',
			'Description'	=> 'Module to scan for PJL enabled printers with no PJL password',
			'Author'	=> 'BrianWGray',
			'License'	=> MSF_LICENSE
		)
		register_options(
			[
				Opt::RPORT(9100),
				OptString.new('PJLPASS', [true, 'Set the PJL password to this number',"0"])			

			], self.class)
	end

	def run_host(ip)
		connect()
		pjldata = datastore['PJLPASS']		

			#Build the PJL string buffer
			buf = "\e%-12345X@PJL JOB\r\n" +
			"@PJL JOB PASSWORD=#{pjldata}\r\n" +
			"@PJL INQUIRE PASSWORD\r\n" +
			"@PJL EOJ\r\n" +
			"\e%-12345X\r\n\x0d\x0a"

			sock.puts(buf)		
			data = sock.recv(1024)

		print_status("Received: #{data} from #{ip}")
		
		                if ( data and data =~ /ENABLED/ )
                                print_status("Printer #{ip} has a PJL password enabled.")
                                report_service(:host => rhost, :port => rport, :name => "PJL Password", :info => data)
                else
                                print_error("Printer #{ip} does not have a PJL password enabled")
                end

		disconnect()
	end

end
