import os
import boto3
import keyboard

from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError, ClientError

# Carregar as variáveis de ambiente do arquivo .env
load_dotenv()

# Obter as credenciais e a região a partir do arquivo .env
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.getenv('AWS_SESSION_TOKEN')
AWS_REGION = os.getenv('AWS_REGION')

def initialize_session(profile_name):
    """
    Inicializa uma sessão boto3 com base no perfil especificado.
    """
    try:
        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            aws_session_token=AWS_SESSION_TOKEN,
            region_name=AWS_REGION
        )
        return session
    except (NoCredentialsError, ClientError) as e:
        print(f"Erro ao inicializar a sessão: {e}\n")
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

def get_resource(session, arn):
    """
    Tenta descrever o recurso com base no ARN. Exemplo: EC2, ACM, etc.
    """
    try:
        if 'acm' in arn:
            client = session.client('acm')  # Cliente para descrever certificados
            cert = client.describe_certificate(CertificateArn=arn)
            return client, cert['Certificate'].get('DomainName', 'Descrição indisponível'), 'acm'
        else:
            print(f"Recurso desconhecido:\n[{arn}]\n")
        return False, False, False
    except ClientError as e:
        print(f"Erro ao descrever o recurso {arn}: {e}\n")
        return False, False, False


def list_resources_and_check_tags(session):
    """
    Lista todos os recursos da região e verifica as tags.
    Se encontrar a tag 'revisao' com o valor 'false', adiciona a tag 'Nome' se não existir.
    """
    try:
        # Inicializar o cliente resourcegroupstaggingapi para listar os recursos com tags
        tagging_client = session.client('resourcegroupstaggingapi')

        paginator = tagging_client.get_paginator('get_resources')

        for page in paginator.paginate():
            resource_tag_mappings = page['ResourceTagMappingList']

            for resource in resource_tag_mappings:
                resource_arn = resource.get('ResourceARN')
                print(f"* Vai iniciar o recurso:\n [{resource_arn}].")
                keyboard.read_event()

                # Verifica se a tecla 'esc' foi pressionada para encerrar o loop
                if keyboard.is_pressed('esc'):
                    print("< Encerrando o programa.")
                    return False
                
                tags = resource.get('Tags', [])

                # Verifica se o recurso tem a tag 'revisao' com o valor 'false'
                tag_revisao = next((tag for tag in tags if tag['Key'] == 'revisao' and tag['Value'] == 'false'), None)

                if tag_revisao:
                    print(f"   1) Recurso com ARN {resource_arn} tem a tag 'revisao' com valor 'false'.\n")
                    # Verificar se a tag 'Nome' já existe
                    tag_nome = next((tag for tag in tags if tag['Key'] == 'Name'), None)

                    if not tag_nome:
                        # Tentar descrever o recurso se não houver a tag 'Nome'
                        client, resource_name, resource_type = get_resource(session, resource_arn)
                        
                        if resource_name:
                            # Adicionar a tag 'Nome' ao recurso
                            print(f"   2) Tenta adicionar a tag 'Nome' ao recurso ARN {resource_arn}.\n")
                            manage_tag_arn(client, resource_arn, resource_type, 'Name', resource_name)
                        else:
                            print(f"   3) Não foi possível adicionar um nome ao recurso ARN {resource_arn}.\n")
                    else:
                        print(f"O recurso {resource_arn} já possui a tag 'Nome'.")
                else:
                    print(f"O recurso {resource_arn} não possui a tag 'revisao' com valor 'false'.\n")
    except (ClientError, NoCredentialsError) as e:
        print(f"Erro ao listar os recursos: {e}\n")

if __name__ == "__main__":
    # Inicializa a sessão boto3 usando as credenciais do arquivo .env
    session = initialize_session()
    
    print(f"AWS_ACCESS_KEY_ID = {AWS_ACCESS_KEY_ID}")
    print(f"AWS_SECRET_ACCESS_KEY = {AWS_SECRET_ACCESS_KEY}")
    print(f"AWS_SESSION_TOKEN = {AWS_SESSION_TOKEN}")
    print(f"AWS_REGION = {AWS_REGION}")
    
    if session:
        print("Listando recursos e verificando tags na região especificada...")
        list_resources_and_check_tags(session)
