import os
import boto3
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError, ClientError

# Carregar as variáveis de ambiente do arquivo .env
load_dotenv()

# Obter as credenciais e a região a partir do arquivo .env
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.getenv('AWS_REGION')

# Inicializar cliente boto3 com as credenciais e região do .env
def initialize_session():
    try:
        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
        return session
    except NoCredentialsError as e:
        print(f"Erro ao carregar credenciais da AWS: {e}")
        return None

def describe_resource(acm_client, resource_arn):
    """
    Tenta descrever o recurso com base no ARN. Exemplo: EC2, ACM, etc.
    """
    try:
        if 'acm' in resource_arn:
            cert = acm_client.describe_certificate(CertificateArn=resource_arn)
            return cert['Certificate'].get('DomainName', 'Descrição indisponível')
        # Aqui você pode adicionar mais descrições para outros tipos de recursos.
        return "Descrição desconhecida"
    except ClientError as e:
        print(f"Erro ao descrever o recurso {resource_arn}: {e}")
        return None

def add_name_tag(resource_arn, resource_name, tagging_client):
    """
    Adiciona a tag "Nome" ao recurso com a descrição fornecida.
    """
    try:
        tagging_client.tag_resources(
            ResourceARNList=[resource_arn],
            Tags={'Nome': resource_name}
        )
        print(f"Tag 'Nome' adicionada ao recurso: {resource_arn} com o valor '{resource_name}'")
    except ClientError as e:
        print(f"Erro ao adicionar tag 'Nome' ao recurso {resource_arn}: {e}")

def list_resources_and_check_tags(session):
    """
    Lista todos os recursos da região e verifica as tags.
    Se encontrar a tag 'revisao' com o valor 'false', adiciona a tag 'Nome' se não existir.
    """
    try:
        # Inicializar o cliente resourcegroupstaggingapi para listar os recursos com tags
        tagging_client = session.client('resourcegroupstaggingapi')
        acm_client = session.client('acm')  # Cliente para descrever certificados

        paginator = tagging_client.get_paginator('get_resources')

        for page in paginator.paginate():
            resource_tag_mappings = page['ResourceTagMappingList']

            for resource in resource_tag_mappings:
                resource_arn = resource.get('ResourceARN')
                tags = resource.get('Tags', [])

                # Verifica se o recurso tem a tag 'revisao' com o valor 'false'
                tag_revisao = next((tag for tag in tags if tag['Key'] == 'revisao' and tag['Value'] == 'false'), None)

                if tag_revisao:
                    print(f"Recurso com ARN {resource_arn} tem a tag 'revisao' com valor 'false'.")

                    # Verificar se a tag 'Nome' já existe
                    tag_nome = next((tag for tag in tags if tag['Key'] == 'Nome'), None)

                    if not tag_nome:
                        # Tentar descrever o recurso se não houver a tag 'Nome'
                        resource_name = describe_resource(acm_client, resource_arn)

                        if resource_name:
                            # Adicionar a tag 'Nome' ao recurso
                            add_name_tag(resource_arn, resource_name, tagging_client)
                    else:
                        print(f"O recurso {resource_arn} já possui a tag 'Nome'.")
                else:
                    print(f"O recurso {resource_arn} não possui a tag 'revisao' com valor 'false'.")
    except (ClientError, NoCredentialsError) as e:
        print(f"Erro ao listar os recursos: {e}")

if __name__ == "__main__":
    # Inicializa a sessão boto3 usando as credenciais do arquivo .env
    session = initialize_session()
    
    if session:
        print("Listando recursos e verificando tags na região especificada...")
        list_resources_and_check_tags(session)
