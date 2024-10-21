import boto3
from botocore.exceptions import NoCredentialsError, ClientError

region = "us-east-1"

def initialize_session(profile_name):
    """
    Inicializa uma sessão boto3 com base no perfil especificado.
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        return session
    except (NoCredentialsError, ClientError) as e:
        print(f"Erro ao inicializar a sessão: {e}")
        return None

def tag_exists(resource_tags, tag_key):
    """
    Verifica se uma tag com o nome 'tag_key' já existe no recurso.
    """
    for tag in resource_tags:
        if tag['Key'] == tag_key:
            return True
    return False

def manage_tag_id(client, resource_id, resource_type, tag_key, tag_value):
    """
    Verifica se a tag 'tag_key' já existe no recurso. Se existir, altera o valor. Se não existir, adiciona.
    """
    try:
        # Obter as tags atuais do recurso
        tags_response = client.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        resource_tags = tags_response['Tags']

        tag_found = False
        # Verifica se a tag 'Name' já existe
        for tag in resource_tags:
            if tag['Key'] == 'Name':
                # Se a tag já existir, atualiza o valor
                if tag['Value'] == 'Descrição da Imagem EC2':
                    client.create_tags(
                        Resources=[resource_id],
                        Tags=[{'Key': tag_key, 'Value': tag_value}]
                    )
                print(f"Tag '{tag_key}' existente atualizada para o {resource_type}: {resource_id}")
                tag_found = True
                break

        # Se a tag não foi encontrada, adiciona a tag 'Name'
        if not tag_found:
            client.create_tags(
                Resources=[resource_id],
                Tags=[{'Key': tag_key, 'Value': tag_value}]
            )
            print(f"Tag '{tag_key}' adicionada ao {resource_type}: {resource_id}")
    except (ClientError, NoCredentialsError) as e:
        print(f"Erro ao gerenciar a tag do {resource_type} ({resource_id}): {e}")

def manage_tag_arn(client, resource_arn, resource_type, tag_key, tag_value):
    """
    Verifica se a tag 'tag_key' já existe no recurso. Se existir, altera o valor. Se não existir, adiciona.
    """
    try:
        # Obter as tags atuais do recurso
        response = client.get_resources(ResourceARNList=[resource_arn])
        resource_tags = response['ResourceTagMappingList'][0]['Tags'] if response['ResourceTagMappingList'] else []

        tag_found = False
        # Verifica se a tag 'Name' já existe
        for tag in resource_tags:
            if tag['Key'] == 'Name':
                # Se a tag já existir, atualiza o valor
                client.create_tags(
                    ResourceARNList=[resource_arn],
                    Tags=[{'Key': tag_key, 'Value': tag_value}]
                )
                print(f"Tag '{tag_key}' existente atualizada para o {resource_type}: {resource_arn}")
                tag_found = True
                break

        # Se a tag não foi encontrada, adiciona a tag 'Name'
        if not tag_found:
            client.create_tags(
                ResourceARNList=[resource_arn],
                Tags=[{'Key': tag_key, 'Value': tag_value}]
            )
            print(f"Tag '{tag_key}' adicionada ao {resource_type}: {resource_arn}")
    except (ClientError, NoCredentialsError) as e:
        print(f"Erro ao gerenciar a tag do {resource_type} ({resource_arn}): {e}")

def list_and_tag_ec2_instances(session):
    """
    Lista e verifica as tags das instâncias EC2, adicionando a tag 'Name' quando necessário.
    """
    ec2 = session.client('ec2')
    instances = ec2.describe_instances()
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{session.region_name}:{instance['OwnerId']}:instance/{instance_id}"
            manage_tag_arn(session.client('resourcegroupstaggingapi'), instance_arn, 'Instância EC2', 'Descrição da instância EC2')

def list_and_tag_s3_buckets(session):
    """
    Lista e verifica as tags dos buckets S3, adicionando a tag 'Name' quando necessário.
    """
    s3 = session.client('s3')
    buckets = s3.list_buckets()

    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        manage_tag_arn(session.client('resourcegroupstaggingapi'), bucket_arn, 'Bucket S3', 'Name', 'Descrição do bucket S3')

def list_and_tag_ebs_volumes(session):
    """
    Lista e verifica as tags dos volumes EBS, adicionando a tag 'Name' quando necessário.
    """
    ec2 = session.client('ec2')
    volumes = ec2.describe_volumes()

    for volume in volumes['Volumes']:
        volume_id = volume['VolumeId']
        volume_arn = f"arn:aws:ec2:{session.region_name}:{volume['OwnerId']}:volume/{volume_id}"
        manage_tag_arn(session.client('resourcegroupstaggingapi'), volume_arn, 'Volume EBS', 'Name', 'Descrição do volume EBS')

def list_and_tag_rds_instances(session):
    """
    Lista e verifica as tags das instâncias RDS, adicionando a tag 'Name' quando necessário.
    """
    rds = session.client('rds')
    instances = rds.describe_db_instances()

    for db_instance in instances['DBInstances']:
        db_instance_arn = db_instance['DBInstanceArn']
        manage_tag_arn(session.client('resourcegroupstaggingapi'), db_instance_arn, 'Instância RDS', 'Name', 'Descrição da instância RDS')

def list_and_tag_lambda_functions(session):
    """
    Lista e verifica as tags das funções Lambda, adicionando a tag 'Name' quando necessário.
    """
    lambda_client = session.client('lambda')
    functions = lambda_client.list_functions()

    for function in functions['Functions']:
        function_arn = function['FunctionArn']
        manage_tag_arn(session.client('resourcegroupstaggingapi'), function_arn, 'Função Lambda', 'Name', 'Descrição da função Lambda')

def list_and_tag_cloudwatch_alarms(session):
    """
    Lista e verifica as tags dos alarmes do CloudWatch, adicionando a tag 'Name' quando necessário.
    """
    cloudwatch = session.client('cloudwatch')
    alarms = cloudwatch.describe_alarms()

    for alarm in alarms['MetricAlarms']:
        alarm_name = alarm['AlarmName']
        alarm_arn = f"arn:aws:cloudwatch:{region}:{session.client('sts').get_caller_identity()['Account']}:alarm:{alarm_name}"
        manage_tag_arn(session.client('resourcegroupstaggingapi'), alarm_arn, 'Alarme CloudWatch', 'Name', f'{alarm_name}')

def list_and_tag_dhcp_options(session):
    """
    Lista e verifica as tags dos EC2 DHCPOptions, adicionando a tag 'Name' quando necessário.
    """
    ec2 = session.client('ec2')
    dhcp_options = ec2.describe_dhcp_options()

    for dhcp_option in dhcp_options['DhcpOptions']:
        dhcp_option_id = dhcp_option['DhcpOptionsId']
        manage_tag_arn(ec2, dhcp_option_id, 'DHCPOptions', 'Name', 'Descrição do DHCPOptions')

def list_and_tag_images(session):
    """
    Lista e verifica as tags das EC2 Images (AMIs), adicionando a tag 'Name' quando necessário.
    """
    ec2 = session.client('ec2')
    images = ec2.describe_images(Owners=['self'])

    for image in images['Images']:
        image_id = image['ImageId']
        manage_tag_id(ec2, image_id, 'Imagem EC2 (AMI)', 'Name', image.get('name','Backup'))

def list_and_tag_internet_gateways(session):
    """
    Lista e verifica as tags dos EC2 InternetGateways, adicionando a tag 'Name' quando necessário.
    """
    ec2 = session.client('ec2')
    internet_gateways = ec2.describe_internet_gateways()

    for gateway in internet_gateways['InternetGateways']:
        gateway_id = gateway['InternetGatewayId']
        manage_tag_id(ec2, gateway_id, 'InternetGateway', 'Name', 'Descrição do InternetGateway')


if __name__ == "__main__":
    # Perfil específico fornecido pelo usuário
    profile_name = "900655431634_Analistas-linux-mkt"
    
    session = initialize_session(profile_name)
    
    if session:
        print("Iniciando a listagem e verificação de tags dos recursos...")

        # EC2
        # list_and_tag_ec2_instances(session)
        
        # S3
        # list_and_tag_s3_buckets(session)
        
        # EBS
        # list_and_tag_ebs_volumes(session)
        
        # RDS
        # list_and_tag_rds_instances(session)
        
        # Lambda
        # list_and_tag_lambda_functions(session)

        # cloudwatch
        # list_and_tag_cloudwatch_alarms(session)

        # list_and_tag_dhcp_options(session)
        
        list_and_tag_images(session)

        # list_and_tag_internet_gateways(session)
        
        print("Processo de verificação e tagueamento concluído.")
