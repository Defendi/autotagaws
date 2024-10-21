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

# Inicializar cliente boto3 com as credenciais e região do .env
def initialize_session():
    try:
        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            aws_session_token=AWS_SESSION_TOKEN,
            region_name=AWS_REGION
        )
        return session
    except NoCredentialsError as e:
        print(f"Erro ao carregar credenciais da AWS: {e}\n")
        return None

def get_acm(session,arn):
    client = session.client('acm')  # Cliente para descrever certificados
    return client.describe_certificate(CertificateArn=arn)

def get_resource(session, arn):
    """
    Tenta descrever o recurso com base no ARN. Exemplo: EC2, ACM, etc.
    """
    try:
        if 'acm' in arn:
            cert = get_acm(session, arn)
            return cert['Certificate'].get('DomainName', 'Descrição indisponível')
        else:
            print(f"Recurso desconhecido:\n[{arn}]\n")
        return False
    except ClientError as e:
        print(f"Erro ao descrever o recurso {arn}: {e}\n")
        return False

def add_name_tag(resource_arn, resource_name, tagging_client):
    """
    Adiciona a tag "Nome" ao recurso com a descrição fornecida.
    """
    try:
        res = tagging_client.tag_resources(
            ResourceARNList=[resource_arn],
            Tags={'Name': resource_name}
        )
        print(f"Resultado ao adicionar a Tag 'Name' ao recurso ARN {resource_arn}:\n{res}\n")
    except ClientError as e:
        print(f"Erro ao adicionar tag 'Nome' ao recurso {resource_arn}: {e}\n")

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
                    tag_nome = next((tag for tag in tags if tag['Key'] == 'Nome'), None)

                    if not tag_nome:
                        # Tentar descrever o recurso se não houver a tag 'Nome'
                        resource_name = get_resource(session, resource_arn)
                        
                        if resource_name:
                            # Adicionar a tag 'Nome' ao recurso
                            print(f"   2) Tenta adicionar a tag 'Nome' ao recurso ARN {resource_arn}.")
                            add_name_tag(resource_arn, resource_name, tagging_client)
                        else:
                            entrada = input("   3) Não foi possível adicionar um nome.\n"
                                            "      Digite um nome, vazio para próximo ou "
                                            "      'sair' para encerrear:\n ")
                            if bool(entrada):
                                if entrada.lower() == 'sair':
                                    return False
                                else:
                                    add_name_tag(resource_arn, entrada, tagging_client)
                    else:
                        print(f"O recurso {resource_arn} já possui a tag 'Nome'.")
                else:
                    print(f"O recurso {resource_arn} não possui a tag 'revisao' com valor 'false'.")
    except (ClientError, NoCredentialsError) as e:
        print(f"Erro ao listar os recursos: {e}")

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
