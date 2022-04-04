import socket
import csv
import sys
import boto3
import sqlite3
# import masscan
import yaml
from multiprocessing import Pool
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from pprint import pprint


#Report do principais ativos internet-faced (portas 22, 3389, 9200, 6379, 5432, 3306, 27017, 2222, 1521 e 1433), RDS´s e Buckets S3 publicos.

all_instances = list()
# ports = range(1, 80)
ports = [80, 8080, 22, 3389, 9200, 6379, 5432, 3306, 27017, 2222, 1521, 1433, 8086]

#PARA IGNORAR TODAS PORTAS DO IP USAR SINTAXE: 3.141.5.46:*
#PARA IGNORAR PORTAS ESPECIFICAS USAR A SINTAXE: 3.141.5.46:22, 3.141.5.46:80
ips_to_ignore = []
sockets_to_ignore = []

def simple_port_scanner(owner, instance, target_ip, fw_open_ports=None):
    '''

    :return:
    '''
    scan_result = []
    try:
        print("Scanning {} - {}...".format(target_ip, owner))

        # will scan ports between 1 to 65,535
        for port in ports:
            if port not in fw_open_ports:
                filtered_ips = filter_scan(target_ip, port)
                if filtered_ips:
                    print("Filtered {} {}".format(target_ip, port))
                    continue
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket.setdefaulttimeout(1)

                    # returns an error indicator
                    result = s.connect_ex((target_ip, port))
                    if result == 0:
                        print("Port {} is open for Address: {}".format(port, target_ip))
                        scan_result.append([target_ip, port, instance, owner])
                    s.close()
            else:
                scan_result.append(["Security Group Rule", target_ip, port, owner])
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


def filter_scan(ip, port):
    '''

    :return:
    '''
    if ip in ips_to_ignore:
        return True
    else:
        for ignore_data in sockets_to_ignore:
            ip_, port_ = ignore_data.split(':')
            if ip_ == ip:
                if port == int(port_):
                    return True
                return False

    # for ignore_data in ips_to_ignore:
        # ip_, port_ = ignore_data.split(':')
        # if ip_ == ip:
        #     if port_ == '*':
        #         return True
        #     if port == int(port_):
        #         return True
        #     return False

def send_mail(config, scan_result):
    '''

    :return:
    '''
    body = ""
    template = '<br>{}</br>'
    for result in scan_result:
        string = template.format(f"{result[0]}, {result[1]}, "
              f" {result[2]}, {result[3]}, {result[4]}, "
              f"  {result[5]}, {result[6]}, {result[7]}")
        body = body + string + "\n"
    mailText = '''<h5> <p>Olá, SOC.</h5>
    	             <h5>Novas máquinas foram criadas na AWS Favor analisar superfície de ataque abaixo:<br>instance id, public_ip, private_ip, region, accountid, port, 
    	             protocol, security group </br>{}.</h5>
    	            <p>&nbsp;</p>'''.format(body)

    # TODO: criar função para enviar email
    # sendmail_novo()

def get_open_ports(security_group_id, ec2_resource):
    open_ports = list()
    secgroup_permissions = ec2_resource.SecurityGroup(security_group_id).ip_permissions
    for permission in secgroup_permissions:
        # print(permission)
        for IpRange in permission['IpRanges']:
            if '0.0.0.0/0' in IpRange.get('CidrIp'):
                if permission.get('ToPort') == '65535':
                    open_ports.append(['65535', security_group_id])
                    break
                elif permission.get('FromPort'):
                    if permission['FromPort'] not in open_ports:
                        open_ports.append([permission['FromPort'], permission['IpProtocol'], security_group_id])
                        continue
                else:
                    # DURANTE OS TESTES PARECEU QUE QUANDO NÃO VEM A CHAVE FromPort ESTA ABERTO
                    # TOTAL E ADICIONEI COMO SE ESTIVESSE 65535 PORTAS ABERTAS. ADICIONADO PROTOCOLO TCP FORÇADO
                    # PARA FACILITAR INDEXAÇÃO PARA PRINTAR O CSV
                    open_ports.append([65535, 'tcp', security_group_id])
    return open_ports


def get_running_instances_details(ec2_client, ec2_resource, region, owner, internet_gateways):
    reservations = ec2_client.describe_instances(Filters=[
        {
            "Name": "instance-state-name",
            "Values": ["running"],
        }
    ]).get("Reservations")

    open_ports = None
    if reservations:
        for reservation in reservations:
            for instance in reservation.get("Instances"):
                if instance.get('VpcId') in internet_gateways:
                    if instance.get('NetworkInterfaces'):
                        for interface in instance['NetworkInterfaces']:
                            if interface.get('Association'):
                                public_ip = interface.get('Association').get('PublicIp')
                                if public_ip and public_ip not in ips_to_ignore:
                                    instance_id = instance.get("InstanceId")
                                    private_ip = instance.get("PrivateIpAddress")
                                    for security_group in instance.get('SecurityGroups'):
                                         open_ports = get_open_ports(security_group['GroupId'], ec2_resource)
                                         if open_ports:
                                             for open_port in open_ports:
                                                # print(f"{instance_id}, {public_ip}, "
                                                #       f" {private_ip}, {region},  {owner}, "
                                                #       f"  {open_ports}")
                                                owner = owner
                                                all_instances.append((instance_id, public_ip, private_ip,
                                                                      region, owner.__str__(), open_port[0], open_port[1],
                                                                      open_port[2]))
    else:
        print("No resources found on {} {}".format(owner, region))


def get_internet_gateways(ec2_obj):
    '''

    :param ec2_obj:
    :return:
    '''
    internet_gateways_list = list()
    internet_gateways = ec2_obj.describe_internet_gateways()
    for i in internet_gateways['InternetGateways']:
        for attachment in i['Attachments']:
            # print(attachment['VpcId'])
            internet_gateways_list.append(attachment['VpcId'])
    return internet_gateways_list

def write_result(all_instances):
    '''

    :return:
    '''
    file_name = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p") + '.csv'
    header = ["Instance ID, Public IP, Private IP, Region, Owner ID, Port, Protocol, Security Group Rules"]
    data = list()
    for result in all_instances:
        data.append([result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7]])

    with open(file_name, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)

        # write the header
        writer.writerow(header)

        # write multiple rows
        writer.writerows(data)

def save_result(result):
    mail_data = list()
    conn = sqlite3.connect('/home/gitlab-runner/data/aws_surface_mapping/resultado.db')
    #DEBUG CONFIG
    # conn = sqlite3.connect('resultado.db')
    cursor = conn.cursor()

    cursor.execute("""
    SELECT instance_id, public_ip, private_ip, region, owner_id, port, protocol, securitygroup FROM resultado;
    """)
    database_log = cursor.fetchall()

    # # inserindo dados na tabela
    for data in result:
        if data not in database_log:
                cursor.execute("""
                INSERT INTO resultado (instance_id, public_ip, private_ip, region, owner_id, port, protocol, securitygroup)
                VALUES {}
                """.format(data))
                mail_data.append(data)
        else:
            pass
    if mail_data:
        send_mail(config.get('mail_list'), mail_data)
    conn.commit()
    conn.close()

def run(config):
    '''

    :return:
    '''
    #:TODO trocar regiões de acordo com a conta.  As contas  costumam ter máquinas somente em São Paulo e Virginia
    regions = ['us-east-2', 'sa-east-1', 'us-east-1']
    for account in config.get('aws_accounts'):
        account_config = config.get('aws_accounts').get(account)
        access_key_id = account_config.get('access_key_id')
        secret_access_key = account_config.get('aws_secret_access_key')
        # Create your own session
        if access_key_id and secret_access_key:
            my_session = boto3.session.Session(aws_access_key_id=access_key_id,
                                               aws_secret_access_key=secret_access_key)
            for region in regions:
                ec2_resource = my_session.resource('ec2', region_name=region)
                ec2_client = my_session.client('ec2', region_name=region)
                internet_gateways = get_internet_gateways(ec2_client)
                get_running_instances_details(ec2_client, ec2_resource, region, account, internet_gateways)
        else:
            print("Use your secret keys for {}".format(account))

    # write_result(all_instances)
    print("Instance ID, Public IP, Private IP, Region, Owner ID, Port, Protocol, Security Group Rules")

    for result in all_instances:
        print(f"{result[0]}, {result[1]}, "
              f" {result[2]}, {result[3]}, '{result[4]}', "
              f"  {result[5]}, {result[6]}, {result[7]}")
    save_result(all_instances)
    ####### PORT SCAN SESSION #########
    # ONE THREAD
    # for ins in all_instances:
    #     if '65535' in ins[3]:
    #         print(simple_port_scanner(ins[0], ins[1], ins[2], ins[3]))

    # MULTITHREAD
    # scan_result = list()
    # futures = []
    # with ThreadPoolExecutor(max_workers=10) as executor:
    #     for ins in all_instances:
    #         if '65535' in ins[3]:
    #             futures.append(executor.submit(simple_port_scanner, ins[0], ins[1], ins[2], ins[3]))
    #         else:
    #             scan_result.append([ins[0], ins[1], ins[2], ins[3]])
    #     for future in concurrent.futures.as_completed(futures):
    #         for result in future.result():
    #             scan_result.append(result)
    # print(scan_result)

if __name__ == '__main__':
    config_path = '/home/gitlab-runner/data/aws_surface_mapping/aws_surface_mapping.yml'
    # DEBUG CONFIG
    # config_path = 'aws_surface_mapping.yml'
    with open(config_path, 'r') as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    run(config)
