import os
from pickle import TRUE
import re
import time

import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from dotenv import load_dotenv
import keyboard

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
        print(f"   Erro ao carregar credenciais da AWS: {e}\n")
        return None

def get_acm(session,arn):
    client = session.client('acm')  # Cliente para descrever certificados
    return client.describe_certificate(CertificateArn=arn)

def get_backup(session,arn):
    client = session.client('backup')  # Cliente para descrever certificados
    return client.describe_protected_resource(ResourceArn=arn)

def get_cloudtrail(session,arn):
    client = session.client('cloudtrail')  # Cliente para descrever certificados
    return client.describe_trails(trailNameList=[arn])

def get_resource(session, arn):
    """
    Tenta descrever o recurso com base no ARN. Exemplo: EC2, ACM, etc.
    """
    try:
        Description = ""
        if 'acm' in arn:
            recurso = get_acm(session, arn)
            Description = recurso['Certificate'].get('DomainName', 'Descrição indisponível')
        elif 'backup' in arn:
            recurso = get_backup(session, arn)
            Description = recurso.get('ResourceName',False)
        elif 'cloudtrail' in arn:
            recurso = get_cloudtrail(session, arn)
            trailList = recurso.get('trailList',[])
            if bool(trailList):
                Description=trailList[0]['name']
        elif 'ec2' in arn and 'network-interface' in arn:
            pass
        else:
            print(f"   Recurso desconhecido:\n[{arn}]\n")
        return re.sub(r'[^a-zA-Z0-9._]', '', Description)
    except ClientError as e:
        print(f"   Erro ao descrever o recurso {arn}: {e}\n")
        return False

def add_name_tag(resource_arn, resource_name, tagging_client):
    """
    Adiciona a tag "Name" ao recurso com a descrição fornecida.
    """
    try:
        res = tagging_client.tag_resources(
            ResourceARNList=[resource_arn],
            Tags={'Name': resource_name}
        )
        fail = res.get('FailedResourcesMap',False)
        if not bool(fail):
            print(f"   Adicionou a Tag 'Name' ao recurso ARN {resource_arn}\n")
            return True
        else:
            print(f"   Falhou ao adicionar a Tag 'Name' ao recurso ARN {resource_arn}:\n{res}\n")
            entrada = input("   Pressione ENTRA para continuar")
            return False
    except ClientError as e:
        print(f"   Erro ao adicionar tag 'Name' ao recurso {resource_arn}: {e}\n")
        return False

def list_resources_and_check_tags(session):
    """
    Lista todos os recursos da região e verifica as tags.
    Se encontrar a tag 'revisao' com o valor 'false', adiciona a tag 'Name' se não existir.
    """
    try:
        # Inicializar o cliente resourcegroupstaggingapi para listar os recursos com tags
        tagging_client = session.client('resourcegroupstaggingapi')

        paginator = tagging_client.get_paginator('get_resources')

        for page in paginator.paginate():
            resource_tag_mappings = page['ResourceTagMappingList']

            for resource in resource_tag_mappings:
                resource_arn = resource.get('ResourceARN')
                print(f"* Vai taguear o recurso:\n   {resource_arn}\n")
                # keyboard.read_event()
                #
                # # Verifica se a tecla 'esc' foi pressionada para encerrar o loop
                # if keyboard.is_pressed('esc'):
                #     print("< Encerrando o programa.\n")
                #     return True
                time.sleep(1) 
                
                tags = resource.get('Tags', [])

                # Verifica se o recurso tem a tag 'revisao' com o valor 'false'
                tag_revisao = next((tag for tag in tags if tag['Key'] == 'revisao' and tag['Value'] == 'false'), None)

                if tag_revisao:
                    print(f"   1) Recurso tem a tag 'revisao' com valor 'FALSE'.\n")
                    # Verificar se a tag 'Name' já existe
                    tag_nome = next((tag for tag in tags if tag['Key'] == 'Name'), None)

                    if not tag_nome:
                        # Tentar descrever o recurso se não houver a tag 'Name'
                        resource_name = get_resource(session, resource_arn)
                        
                        if resource_name:
                            # Adicionar a tag 'Name' ao recurso
                            print(f"   2) Tenta adicionar a tag 'Name' = {resource_name} ao recurso.\n")
                            add_name_tag(resource_arn, resource_name, tagging_client)
                        else:
                            entrada = input("   3) Não foi possível adicionar um Name.\n"
                                            "      Digite um Name, vazio para próximo ou "
                                            "      'sair' para encerrear:\n ")
                            if bool(entrada):
                                if entrada.lower() == 'sair':
                                    return False
                                else:
                                    add_name_tag(resource_arn, entrada, tagging_client)
                    else:
                        print(f"   O recurso já possui a tag 'Name'.\n")
                else:
                    print(f"   O recurso não possui a tag 'revisao' com valor 'false'.\n")
                print("************************************************************************************\n")
    except (ClientError, NoCredentialsError) as e:
        print(f"   Erro ao listar os recursos: {e}")

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
