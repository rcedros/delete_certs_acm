import boto3
from botocore.exceptions import ClientError
import csv

arn_roles = [
    "arn:aws:iam::111111111111:role/role-remove-unused-certs-acm",
    "arn:aws:iam::222222222222:role/role-remove-unused-certs-acm",
    "arn:aws:iam::333333333333:role/role-remove-unused-certs-acm",
    "arn:aws:iam::444444444444:role/role-remove-unused-certs-acm"
    ]

regions = ['us-west-1', 'us-west-2', 'us-east-1', 'us-east-2', 'sa-east-1']

def assumed_role(role_arn, service, region):
    try:
        sts_client = boto3.client('sts', region_name=region)
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumedSession"
        )

        credentials = assumed_role['Credentials']

        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region  # Especificar região para a sessão
        )
        return session.client(service, region_name=region)
    except ClientError as e:
        print(f"Erro ao assumir role {role_arn}: {e}")
        return None

def get_acm_summary():
    listcert = []
    for role_arn in arn_roles:
        for region in regions:
            acm_client = assumed_role(role_arn, "acm", region)
            if acm_client is not None:
                try:
                    paginator = acm_client.get_paginator('list_certificates')
                    page_iterator = paginator.paginate(
                        PaginationConfig={'PageSize': 10})

                    for page in page_iterator:
                        for cert in page['CertificateSummaryList']:
                            if cert['InUse'] == True and cert['Status'] == "EXPIRED":
                                certs = cert['Status'], cert['InUse'], cert['DomainName'], region, role_arn, cert['CertificateArn']
                                listcert.append(certs)
                except Exception as e:
                    print(f"Erro ao listar certificados na conta {role_arn.split(':')[:4]} na região {region}: {e}")
    return listcert

file_path = 'list_acm_certificates_expired.csv'

with open(file_path, 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    header = ["status", "in_use", "common_name", "region", "role_arn", "certitificate_arn"]
    csv_writer.writerow(header)
    for entry in get_acm_summary():
        csv_writer.writerow(entry)


# with open(file_path, 'r', newline='') as csvfile:
#     csv_reader = csv.reader(csvfile)
#     next(csv_reader)  # Pula o cabeçalho
#     for row in csv_reader:
#         arn_role, region, _, _, certificate_arn = row
#         acm_client = assumed_role(arn_role, "acm", region)
#         if acm_client is not None:
#             try:
#                 response = acm_client.delete_certificate(CertificateArn=certificate_arn)
#                 print(f"Certificado excluído com sucesso: {certificate_arn}")
#             except acm_client.exceptions.ResourceInUseException:
#                 print(f"Erro: O certificado está em uso e não pode ser excluído: {certificate_arn}")
#             except Exception as e:
#                 print(f"Erro ao excluir o certificado {certificate_arn}: {e}")
