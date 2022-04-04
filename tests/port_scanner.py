import sys, socket


ports = [80, 8080, 22, 3389, 9200, 6379, 5432, 3306, 27017, 2222, 1521, 1433, 8086, 8005]

def simple_port_scanner(owner, target):
    '''

    :return:
    '''
    scan_result = []
    public_ip_address = target
    try:
        print("Scanning {} - {}...".format(public_ip_address, owner))

        # will scan ports between 1 to 65,535
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            # returns an error indicator
            result = s.connect_ex((public_ip_address, port))
            if result == 0:
                print("Port {} is open for Address: {}".format(port, public_ip_address))
                scan_result.append([public_ip_address, port, owner])
            s.close()
        return scan_result

    except KeyboardInterrupt:
        print("\n Exitting Program !!!!")
        sys.exit()
    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")
        sys.exit()
    except socket.error:
        print("\ Server not responding !!!!")
        sys.exit()

if __name__ == '__main__':
    ips = ['18.229.58.182']
    for ip in ips:
        simple_port_scanner('dd', ip)
