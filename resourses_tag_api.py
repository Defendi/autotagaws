import os
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

def add_name_tag(resource_arn, tag_name, resource_name, tagging_client):
    """
    Adiciona a tag "Name" ao recurso com a descrição fornecida.
    """
    try:
        res = tagging_client.tag_resources(
            ResourceARNList=[resource_arn],
            Tags={tag_name: resource_name}
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

def get_ie(valor: str):
    
    res = "geral-anima"
    if 'ages' in valor:
        res = 'ages'
    elif 'bsp' in valor: 
        res = 'ages'
    elif 'centrouniversitariounifg' in valor: 
        res = 'ages'
    elif 'ebradi' in valor: 
        res = 'ages'
    elif 'fadergs' in valor: 
        res = 'ages'
    elif 'fapa' in valor: 
        res = 'ages'
    elif 'faseh' in valor: 
        res = 'ages'
    elif 'fpb' in valor: 
        res = 'ages'
    elif 'hsm' in valor: 
        res = 'ages'
    elif 'hsmu' in valor: 
        res = 'ages'
    elif 'ibmr' in valor: 
        res = 'ages'
    elif 'inspirali' in valor: 
        res = 'ages'
    elif 'lecordonbleu' in valor: 
        res = 'ages'
    elif 'mcampos' in valor: 
        res = 'ages'
    elif 'onelearning' in valor: 
        res = 'ages'
    elif 'uam' in valor or 'anhembi' in valor: 
        res = 'ages'
    elif 'una' in valor: 
        res = 'ages'
    elif 'unibh' in valor: 
        res = 'ages'
    elif 'unicuritiba' in valor: 
        res = 'ages'
    elif 'unifacs' in valor: 
        res = 'ages'
    elif 'unifg' in valor: 
        res = 'ages'
    elif 'uniritter' in valor: 
        res = 'ages'
    elif 'unisociesc' in valor: 
        res = 'ages'
    elif 'unisul' in valor: 
        res = 'ages'
    elif 'unp' in valor: 
        res = 'ages'
    elif 'usjt' in valor: 
        res = 'ages'
    return res
    
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
                tag_name = next((tag for tag in tags if tag['Key'] == 'Name'), None)

                if not tag_name:
                    # Tentar descrever o recurso se não houver a tag 'Name'
                    resource_name = get_resource(session, resource_arn)
                    
                    if resource_name:
                        # Adicionar a tag 'Name' ao recurso
                        print(f"   2) Tenta adicionar a tag 'Name' = {resource_name} ao recurso.\n")
                        add_name_tag(resource_arn, "Name", resource_name, tagging_client)
                    else:
                        resource_name = input("   3) Não foi possível adicionar um Name.\n"
                                              "      a) Digite um Nome para o recurso;\n"
                                              "      b) Tecle enter vazio para não adicionar e ir ao próximo;\n"
                                              "      c) Digite 'sair' para encerrear:\n ")
                        if bool(resource_name):
                            if resource_name.lower() == 'sair':
                                return False
                            else:
                                print(f"   2) Tenta adicionar a tag 'Name' = {resource_name} ao recurso.\n")
                                add_name_tag(resource_arn, "Name", resource_name, tagging_client)
                else:
                    resource_name = tag_name['Value']
                if bool(resource_name):
                    tag_ambiente    = next((tag for tag in tags if tag['Key'] == 'ambiente'), None)
                    tag_squad       = next((tag for tag in tags if tag['Key'] == 'squad'), None)
                    tag_area        = next((tag for tag in tags if tag['Key'] == 'area'), None)
                    tag_servico     = next((tag for tag in tags if tag['Key'] == 'servico'), None)
                    tag_produto     = next((tag for tag in tags if tag['Key'] == 'produto'), None)
                    tag_projeto     = next((tag for tag in tags if tag['Key'] == 'Name'), None)
                    tag_ie          = next((tag for tag in tags if tag['Key'] == 'instituicao-ensino' or tag['Key'] == 'ie'), None)
                    tag_backup      = next((tag for tag in tags if tag['Key'] == 'Name'), None)
                    tag_costcenter  = next((tag for tag in tags if tag['Key'] == 'Name'), None)
                    tag_dynatrace   = next((tag for tag in tags if tag['Key'] == 'Name'), None)
                    tag_revisao     = next((tag for tag in tags if tag['Key'] == 'Name'), None)
                    if not bool(tag_ambiente):
                        ambiente = "hml" if "hml" in resource_name else "prd"
                    else:
                        ambiente = tag_ambiente['Value']
                    if not bool(tag_squad):
                        squad = "graduacao"
                        if 'pos' in resource_name:
                            squad = "pos"
                        elif 'ead' in resource_name:
                            squad = "ead"
                        
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
